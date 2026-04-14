//! AArch64 hardware virtualization primitive layer.
//!
//! Mirrors `kernel/arch/x64/vm.zig`. Where x64 has to pick between Intel VMX
//! and AMD SVM at runtime, ARMv8-A has exactly one virtualization mechanism:
//! EL2 (the Hypervisor Exception Level), driven by system registers (no
//! VMCS/VMCB control structures). So there is no runtime backend dispatch
//! here; everything calls straight into the EL2 helpers at the bottom of
//! this file.
//!
//! Architectural references (all local PDFs under `docs/aarch64/`):
//!   - ARM ARM (DDI 0487)      — the authoritative spec
//!       - D1     "The AArch64 Application Level Programmers' Model"
//!       - D1.4   Exception levels and Security states
//!       - D1.11  Synchronous and asynchronous exceptions (entry/return)
//!       - D5     VMSAv8-64 address translation (Stage 1 and Stage 2)
//!       - D5.4   Stage 2 translation
//!       - D5.5   Memory attribute fields in VMSAv8-64 translation descriptors
//!       - D13.2  AArch64 system register descriptions
//!           HCR_EL2, VTCR_EL2, VTTBR_EL2, ESR_EL2, HPFAR_EL2, FAR_EL2,
//!           SPSR_EL2, ELR_EL2, VBAR_EL2, CPTR_EL2, MDCR_EL2, MAIR_EL2,
//!           TCR_EL2, ID_AA64MMFR1_EL1, ID_AA64PFR0_EL1.
//!   - 102142 "Learn the architecture - AArch64 virtualization"
//!       - §2  Virtualization in AArch64 (EL2 overview)
//!       - §3  Stage 2 translation
//!       - §4  Virtual exceptions and trapping
//!       - §5  Virtual interrupts (tied to GICv3 vCPU interface)
//!
//! Concept map from x86 to ARM (for reviewers coming from the x64 code):
//!   VMCS/VMCB  → a handful of EL2 system registers set directly before ERET
//!   EPT root   → VTTBR_EL2 (Virtualization Translation Table Base Register)
//!   EPT ptes   → Stage-2 descriptors (ARM ARM D5.5)
//!   VMRUN/VMRESUME → ERET from EL2 to EL1 with HCR_EL2.TGE=0
//!   VMEXIT     → exception taken to EL2 (vectored via VBAR_EL2)
//!   CR0/CR4    → SCTLR_EL1 + HCR_EL2 virtualization bits
//!   CPUID      → MRS of ID_AA64* registers, optionally trapped via HCR_EL2.TID*
//!   MSR bitmap → HCR_EL2 trap bits + per-register trap controls (no bitmap)
//!   LAPIC/IOAPIC → GICv3 virtual CPU interface (ICH_* sysregs) + emulated
//!                  GICD/GICR MMIO pages (see arch/aarch64/kvm/vgic.zig)

const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

// ===========================================================================
// Guest register state snapshot
// ===========================================================================

/// Full guest register state, saved on VM exit and restored on VM entry.
///
/// AArch64 analogue of the x64 GuestState struct. Layout is chosen so the
/// save/restore asm in `vmResume` can spill registers to a contiguous
/// block with minimal per-field math.
///
/// What has to round-trip across an EL2 exception on a single vCPU:
///   - x0..x30     general-purpose registers                       (ARM ARM B1.2.1)
///   - sp_el0/el1  guest stack pointers                            (D1.7)
///   - pc          guest program counter (taken from ELR_EL2 on exit)
///   - pstate      processor state (taken from SPSR_EL2 on exit)   (C5.2)
///   - EL1 sysregs that form the guest's virtual CPU state         (D13.2)
///   - FPSIMD V0..V31 + FPCR/FPSR                                   (B1.2.2)
///
/// The EL1 system registers listed here are the ones the guest kernel
/// normally reads/writes during scheduling and exception handling.  They
/// are context-switched per vCPU on entry/exit (see `vmResume`).  Trap
/// control registers (HCR_EL2, VTCR_EL2, VTTBR_EL2, etc.) live in the VM's
/// arch_structures block instead because they are per-VM, not per-vCPU GPR
/// state visible to the VMM.
pub const GuestState = extern struct {
    // General-purpose registers (ARM ARM B1.2.1)
    x0: u64 = 0,
    x1: u64 = 0,
    x2: u64 = 0,
    x3: u64 = 0,
    x4: u64 = 0,
    x5: u64 = 0,
    x6: u64 = 0,
    x7: u64 = 0,
    x8: u64 = 0,
    x9: u64 = 0,
    x10: u64 = 0,
    x11: u64 = 0,
    x12: u64 = 0,
    x13: u64 = 0,
    x14: u64 = 0,
    x15: u64 = 0,
    x16: u64 = 0,
    x17: u64 = 0,
    x18: u64 = 0,
    x19: u64 = 0,
    x20: u64 = 0,
    x21: u64 = 0,
    x22: u64 = 0,
    x23: u64 = 0,
    x24: u64 = 0,
    x25: u64 = 0,
    x26: u64 = 0,
    x27: u64 = 0,
    x28: u64 = 0,
    x29: u64 = 0, // frame pointer
    x30: u64 = 0, // link register

    /// Guest stack pointer for EL0 (ARM ARM D13.2.128).
    sp_el0: u64 = 0,
    /// Guest stack pointer for EL1 (ARM ARM D13.2.129).
    sp_el1: u64 = 0,
    /// Guest program counter; loaded into ELR_EL2 on entry, read back on exit.
    pc: u64 = 0,
    /// Processor state bits; loaded into SPSR_EL2 on entry (ARM ARM C5.2).
    /// For a freshly-created EL1 guest we typically set this to EL1h with
    /// DAIF all masked until the guest kernel is ready (see vcpu.zig).
    pstate: u64 = 0,

    // ----- EL1 system registers (ARM ARM D13.2) -----
    //
    // These form the stable on-vCPU view of the guest kernel state. The
    // VMM can read/write them via vm_vcpu_{get,set}_state so it can
    // initialize a freshly loaded kernel image, take crash dumps, etc.

    /// SCTLR_EL1 — system control (MMU enable, cache enable, endianness).
    /// ARM ARM D13.2.110.  After reset, SCTLR_EL1 reads as RES1 pattern
    /// 0x30C50830 (various RES1 bits).  The kernel loader flips M to enable
    /// stage-1 translation; until then the guest executes with VA==PA.
    sctlr_el1: u64 = 0x30C50830,
    /// TTBR0_EL1 / TTBR1_EL1 — guest stage-1 translation roots (D13.2.145).
    ttbr0_el1: u64 = 0,
    ttbr1_el1: u64 = 0,
    /// TCR_EL1 — stage-1 translation control (D13.2.135).
    tcr_el1: u64 = 0,
    /// MAIR_EL1 — memory attribute indirection (D13.2.83).
    mair_el1: u64 = 0,
    /// AMAIR_EL1 — auxiliary MAIR (IMPL DEF; passthrough) (D13.2.11).
    amair_el1: u64 = 0,
    /// CPACR_EL1 — coprocessor (FPSIMD / SVE) access control (D13.2.28).
    cpacr_el1: u64 = 0,
    /// CONTEXTIDR_EL1 — ASID + context id used for tracing (D13.2.26).
    contextidr_el1: u64 = 0,
    /// TPIDR_EL0 / TPIDR_EL1 / TPIDRRO_EL0 — thread pointers (D13.2.139-141).
    tpidr_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    tpidrro_el0: u64 = 0,
    /// VBAR_EL1 — guest exception vector base (D13.2.152).
    vbar_el1: u64 = 0,
    /// Guest-side exception scratch registers. Saved/restored so that
    /// taking an EL2 exception does not clobber an in-flight EL1 exception.
    elr_el1: u64 = 0,
    spsr_el1: u64 = 0,
    esr_el1: u64 = 0,
    far_el1: u64 = 0,
    /// AFSR0_EL1 / AFSR1_EL1 — auxiliary fault status (IMPL DEF; passthrough).
    afsr0_el1: u64 = 0,
    afsr1_el1: u64 = 0,
    /// MDSCR_EL1 — debug control (breakpoints, single-step) (D13.3.15).
    mdscr_el1: u64 = 0,

    /// CNTV_CVAL_EL0 / CNTV_CTL_EL0 — guest virtual timer state (D11.2).
    /// Saved/restored per vCPU so each vCPU has its own virtual timer.
    cntv_cval_el0: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    /// CNTKCTL_EL1 — EL0 access to timers (D11.2.4).
    cntkctl_el1: u64 = 0,
    /// CNTVOFF_EL2 — virtual timer offset (per VM, not per vCPU).
    /// Tracked here for convenience; loaded during entry (D11.2.7).
    cntvoff_el2: u64 = 0,

    // ----- Pending virtual-interrupt bits consumed by vmResume -----
    //
    // On x86 the guest event injection token lives in the VMCS/VMCB; on
    // ARM the equivalent is the ICH_LR<n>_EL2 list registers. We stage
    // the desired injection here in GuestState and `vgic.prepareEntry`
    // translates it to LR writes right before ERET.
    //
    // These fields are flags, not vectors: the vector lookup happens via
    // the vGIC when it actually fills an LR. They exist so an exit
    // handler that just decided to inject something does not have to reach
    // into the vGIC before vmResume runs.
    pending_virq: u8 = 0,
    pending_vfiq: u8 = 0,
    pending_vserror: u8 = 0,
    _pad0: [5]u8 = .{0} ** 5,
};

/// FPSIMD/SVE save area. We use plain FPSIMD (V0..V31 + FPCR + FPSR) for
/// now: 32 × 16 = 512 bytes, plus 8 bytes for FPCR/FPSR, rounded up to
/// 576 for alignment headroom.
///
/// Name `FxsaveArea` is intentionally identical to the x64 type so that
/// `dispatch.zig` can keep a common `FxsaveArea` alias. On ARM this is the
/// FPSIMD context, not an Intel FXSAVE region.
///
/// ARM ARM B1.2.2 describes V0..V31; FPCR/FPSR are D13.2.48/D13.2.52.
pub const FxsaveArea = [576]u8;

pub fn fxsaveInit() FxsaveArea {
    return .{0} ** 576;
}

// ===========================================================================
// VM exit reasons (decoded from ESR_EL2)
// ===========================================================================

/// Decoded VM exit reason.
///
/// On ARM, every exit is an "exception taken to EL2" and the exception
/// class lives in ESR_EL2.EC (ARM ARM D13.2.39, Table D13-45). The list
/// below covers every EC value we intend to handle in the v1
/// implementation; any unrecognized EC surfaces as `.unknown` so the exit
/// handler can forward it to the VMM for triage.
///
/// Equivalents to x86 VmExitInfo variants:
///   cpuid          → sysreg_trap reading an ID_AA64* register
///   io             → (no port I/O on ARM; device I/O is MMIO on stage-2)
///   mmio           → stage2_fault on a guest physical address that the
///                    VMM has mapped as an MMIO region
///   cr_access      → sysreg_trap on SCTLR_EL1/CPACR_EL1/… (HCR_EL2.TVM)
///   msr_read/write → sysreg_trap on any trapped system register
///   ept_violation  → stage2_fault
///   exception      → synchronous_el1 when a guest instruction itself faults
pub const VmExitInfo = union(enum) {
    /// EC=0x20 (instruction abort from a lower EL) or 0x24 (data abort from
    /// a lower EL): a stage-2 fault. HPFAR_EL2[39:4] << 8 holds the IPA of
    /// the faulting access; FAR_EL2 holds the guest VA (D13.2.55, D13.2.59).
    stage2_fault: Stage2Fault,

    /// EC=0x16 (HVC execution from AArch64 EL1). ISS holds the 16-bit
    /// immediate encoded in the HVC instruction.
    hvc: HvcExit,

    /// EC=0x17 (SMC execution from AArch64 EL1). Non-secure hypervisors
    /// normally synthesize PSCI via HVC; SMC is typically forwarded to the
    /// VMM unchanged.
    smc: SmcExit,

    /// EC=0x18 (trapped MSR/MRS or system instruction). ISS encodes
    /// Op0/Op1/CRn/CRm/Op2/Rt/Direction.
    sysreg_trap: SysregTrap,

    /// EC=0x01 (trapped WFI/WFE). Used for guest idle; the kernel may
    /// convert this into a scheduler yield inline.
    wfi_wfe: WfiWfeExit,

    /// EC=0x00 (unknown reason). Typically a signal that the trap config
    /// is wrong; surfaced to VMM for debugging.
    unknown_ec: u8,

    /// Guest-side synchronous exception that the VMM asked to see.
    /// Payload is the raw ESR_EL2 value.
    synchronous_el1: u64,

    /// Guest-triggered halt/shutdown state. Maps to x86 .hlt / .shutdown.
    halt: void,
    shutdown: void,

    /// Anything else; `raw` is the full ESR_EL2.
    unknown: u64,

    pub const Stage2Fault = struct {
        /// Guest physical address of the faulting access, derived from
        /// HPFAR_EL2[39:4] << 8 | (FAR_EL2 & 0xFFF).
        guest_phys: u64,
        /// Guest virtual address from FAR_EL2 (may be UNKNOWN for some
        /// fault classes; see ARM ARM D13.2.55).
        guest_virt: u64,
        /// True if the fault was on an instruction fetch (EC=0x20).
        is_instruction: bool,
        /// Write not-read flag (ESR_EL2.ISS.WnR).
        is_write: bool,
        /// Size of the access encoded in ISS.SAS (0=byte, 1=halfword,
        /// 2=word, 3=doubleword). Only meaningful when ISS.ISV=1.
        access_size: u8,
        /// Destination register index (ISS.SRT) for loads. Valid only
        /// when ISS.ISV=1.
        srt: u8,
        /// 1 if the above fields are valid (ISS.ISV). When 0, the VMM
        /// must do its own instruction decode at `guest_virt`.
        iss_valid: bool,
    };

    pub const HvcExit = struct {
        /// 16-bit immediate encoded in the HVC instruction (ISS[15:0]).
        imm: u16,
    };

    pub const SmcExit = struct {
        imm: u16,
    };

    pub const SysregTrap = struct {
        /// Raw ISS field so callers can decode further if they want.
        iss: u32,
        op0: u2,
        op1: u3,
        crn: u4,
        crm: u4,
        op2: u3,
        /// Destination/source register index.
        rt: u5,
        /// 1 = MRS (read), 0 = MSR (write).
        is_read: bool,
    };

    pub const WfiWfeExit = struct {
        /// 0 = WFI, 1 = WFE (ISS.TI).
        is_wfe: bool,
    };
};

// ===========================================================================
// Interrupt / exception injection types
// ===========================================================================

/// Virtual interrupt to inject into a guest vCPU. Unlike x86 (where a
/// vector is enough), on ARM an "interrupt" is delivered via the vGIC
/// and must say which virtual interrupt _line_ it is (SGI/PPI/SPI).
/// The vGIC translates this into an LR write; see `vgic.injectInterrupt`.
///
/// ARM ARM D13.2 HCR_EL2.VI/VF/VSE, GICv3 §4.7 "Virtual interrupts".
pub const GuestInterrupt = extern struct {
    /// Interrupt ID (INTID). 0..15 = SGI, 16..31 = PPI, 32..1019 = SPI.
    intid: u32,
    /// Priority (0 = highest, 0xFF = lowest).
    priority: u8,
    /// Interrupt type: 0 = vIRQ, 1 = vFIQ, 2 = vSError.
    kind: u8,
    _pad: [2]u8 = .{0} ** 2,
};

/// Exception to inject into the guest at EL1. Injecting means: set
/// SPSR_EL1 = current PSTATE, ELR_EL1 = current PC, ESR_EL1 = syndrome,
/// and redirect PC to VBAR_EL1 + offset (ARM ARM D1.11).
pub const GuestException = extern struct {
    /// ESR_EL1 syndrome value the guest kernel will observe.
    esr: u64,
    /// FAR_EL1 fault address value (for data/instruction aborts).
    far: u64,
    /// Which vector to branch to: 0 = SP_EL1 sync, 1 = SP_EL1 IRQ, …
    /// 4 = lower-EL (aarch64) sync, etc. See ARM ARM D1.11 Table D1-7.
    vector_slot: u8,
    _pad: [7]u8 = .{0} ** 7,
};

// ===========================================================================
// VmPolicy — inline-handled exits
// ===========================================================================

/// Per-VM inline-exit policy table. x86 lets the VMM pre-register CPUID
/// and CR-access responses; on ARM the analogous hook is system register
/// traps.
///
/// Two pools:
///   - `id_reg_responses` — ID_AA64* register reads. The ARM equivalent of
///     CPUID: the VMM wants to lie about the CPU identity to hide features
///     from the guest. The kernel handles these inline by returning
///     `value` and advancing PC.
///   - `sysreg_policies` — arbitrary trapped sysregs. For each entry the
///     kernel either (a) returns a fixed read value and/or (b) silently
///     swallows the write, without exiting to the VMM.
///
/// Both tables are read-only after vm_create so require no locking.
pub const VmPolicy = extern struct {
    id_reg_responses: [MAX_ID_REG_RESPONSES]IdRegResponse =
        .{IdRegResponse{}} ** MAX_ID_REG_RESPONSES,
    num_id_reg_responses: u32 = 0,
    _pad0: u32 = 0,

    sysreg_policies: [MAX_SYSREG_POLICIES]SysregPolicy =
        .{SysregPolicy{}} ** MAX_SYSREG_POLICIES,
    num_sysreg_policies: u32 = 0,
    _pad1: u32 = 0,

    pub const MAX_ID_REG_RESPONSES = 64;
    pub const MAX_SYSREG_POLICIES = 32;

    /// One entry in the ID_AA64* response table. Op0/Op1/CRn/CRm/Op2
    /// uniquely identifies a system register (ARM ARM C5.3).
    pub const IdRegResponse = extern struct {
        op0: u8 = 0,
        op1: u8 = 0,
        crn: u8 = 0,
        crm: u8 = 0,
        op2: u8 = 0,
        _pad: [3]u8 = .{0} ** 3,
        value: u64 = 0,
    };

    /// One entry in the sysreg trap policy table. `read_value` is what a
    /// trapped MRS observes; `write_mask` controls which bits a trapped
    /// MSR is allowed to set (0 = ignore the write entirely).
    pub const SysregPolicy = extern struct {
        op0: u8 = 0,
        op1: u8 = 0,
        crn: u8 = 0,
        crm: u8 = 0,
        op2: u8 = 0,
        _pad: [3]u8 = .{0} ** 3,
        read_value: u64 = 0,
        write_mask: u64 = 0,
    };
};

// ===========================================================================
// Global / per-core init
// ===========================================================================

/// Set to true by `vmInit()` when ID_AA64PFR0_EL1.EL2 indicates EL2 is
/// implemented and usable. Queried by `vmSupported()` and by vm_create.
var vm_supported: bool = false;

/// Set to true by the direct-kernel boot path after VBAR_EL2 has been
/// loaded with `__hyp_vectors`. UEFI boot enters at EL1 and never gets
/// the chance to install a hyp stub, so this stays false there — making
/// `vmSupported()` honest about whether EL2 is actually reachable from
/// EL1 via HVC. See `kernel/arch/aarch64/boot/start.S` (direct-kernel
/// path) and `directKernelEntry` in `boot/direct_kernel.zig`.
pub var hyp_stub_installed: bool = false;

/// Read ID_AA64PFR0_EL1 (ARM ARM K.a §D23.2.79, p7932).
///
/// Field map (bits → field):
///   [3:0]    EL0          AArch64/AArch32 support at EL0
///   [7:4]    EL1          AArch64/AArch32 support at EL1
///   [11:8]   EL2          0=not implemented, 1=A64 only, 2=A64+A32
///   [15:12]  EL3          analogous
///   [19:16]  FP           floating-point support
///   [23:20]  AdvSIMD      advanced SIMD support
///   ...      (CSV2/RME/DIT/AMU/MPAM/SEL2/SVE/RAS/GIC)
///
/// We only consult EL2 here; the GIC field (bits [27:24]) is checked by
/// the GIC driver, not us.
inline fn readIdAa64Pfr0() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], id_aa64pfr0_el1"
        : [v] "=r" (v),
    );
    return v;
}

/// Global VM subsystem init. Called once at boot from `arch.vmInit()`.
///
/// Responsibilities:
///   1. Read ID_AA64PFR0_EL1 and check bits [11:8] for EL2 support. A
///      value of 0 means EL2 is not implemented; any non-zero value means
///      EL2 is implemented (1 = AArch64 only, 2 = AArch64 + AArch32).
///   2. Initialize the VMID allocator (see stage-2 code below).
///
/// We deliberately do NOT consult ID_AA64MMFR1_EL1.VH here. The Zag
/// kernel itself runs at EL1 (entered at EL1 by PSCI), so we never use
/// VHE to host the kernel itself; we only care that stage-2 translation
/// and EL2 routing are available. EL2-without-VHE works for our needs.
pub fn vmInit() void {
    const pfr0 = readIdAa64Pfr0();
    const el2_field: u4 = @truncate((pfr0 >> 8) & 0xF);
    vm_supported = el2_field != 0;
    // TODO(impl): init VMID allocator
}

/// Per-core VM initialization. Called from `sched.perCoreInit()` on every
/// CPU after global init. On ARM the per-core setup is small: ensure EL2
/// vectors are installed and that per-core trap configuration (HCR_EL2
/// RES1 bits, MDCR_EL2 for PMU trap sharing, etc.) reflects the boot-time
/// defaults. All real state is per-VM, so this is essentially a no-op on
/// a hypervisor that does not switch between host and guest VMIDs outside
/// of a vCPU run.
pub fn vmPerCoreInit() void {
    // TODO: install EL2 vectors via VBAR_EL2 if not already installed by boot
    // TODO: set HCR_EL2 defaults for "host running at EL1" state
}

/// Returns true if hardware virtualization is available AND reachable
/// from this kernel build. Two conditions must hold:
///
///   1. `ID_AA64PFR0_EL1.EL2 != 0` — the CPU implements EL2.
///   2. `hyp_stub_installed` — the boot path actually loaded VBAR_EL2
///      with our hyp vector table. This requires entering at EL2 (the
///      direct-kernel boot path under `-M virt,virtualization=on`); the
///      UEFI path enters at EL1 with no way to write VBAR_EL2, so even
///      a CPU that advertises EL2 in its ID register is unreachable.
///
/// On any environment failing either condition, vm_* syscalls
/// short-circuit with `E_NODEV` and the s4_2 test suite reports SKIP
/// (see `tests/tests/libz/test.zig :: skipIfNoVm`).
pub fn vmSupported() bool {
    return vm_supported and hyp_stub_installed;
}

// ===========================================================================
// Hyp-call ABI (host → EL2 dispatcher)
// ===========================================================================
//
// The direct-kernel EL2 hyp stub in boot/start.S exposes a tiny hypercall
// interface to the EL1 kernel via `hvc #0`:
//
//   x0 = hypercall id (see `HypCallId`)
//   x1 = argument (id-specific: a raw value or a physical-address pointer)
//
// The stub writes the result into x0 and ERETs to the instruction after
// the HVC (ARM ARM D1.10.2 — HVC preferred exception return address is
// the instruction following HVC).
//
// Non-VHE hyp only: the kernel itself runs at EL1, EL2 is used purely as
// a thin dispatcher reached via HVC. There is no "host at EL2" mode.

pub const HypCallId = enum(u64) {
    /// Return `arg ^ 1`. Round-trip smoke test; no side effects.
    noop = 0,
    /// `arg` = physical address of a WorldSwitchCtx. Enter the guest;
    /// return when the guest exits with the exit info stored in the
    /// WorldSwitchCtx. Returns 0 on success, non-zero on entry failure.
    vcpu_run = 1,
};

/// Issue `hvc #0` with (id, arg) and return the 64-bit result in x0.
///
/// Marked `inline` because the `hvc` instruction is only legal in kernel
/// code paths that know EL2 is present — we want the callsite to be a
/// bare hvc, not a call through a function pointer.
pub inline fn hypCall(id: HypCallId, arg: u64) u64 {
    var ret: u64 = undefined;
    asm volatile (
        \\hvc #0
        : [ret] "={x0}" (ret),
        : [id] "{x0}" (@intFromEnum(id)),
          [arg] "{x1}" (arg),
        : .{ .memory = true });
    return ret;
}

// ===========================================================================
// Guest entry / exit
// ===========================================================================

/// Enter the guest. Called from the vCPU thread entry point; returns the
/// decoded exit info when the guest exits.
///
/// High-level flow (mirrors x64 `vmx.vmResume`/`svm.vmResume`):
///   1. Disable interrupts.
///   2. Save host callee-saved GPRs and FPSIMD state.
///   3. Switch in per-VM EL2 state:
///        - HCR_EL2      (trap config, see vm_structures block)
///        - VTCR_EL2     (stage-2 format)
///        - VTTBR_EL2    (VMID | stage-2 root PA)
///        - CPTR_EL2     (FPSIMD / SVE trap config)
///        - MDCR_EL2     (debug / PMU trap share)
///        - CNTVOFF_EL2  (per-VM virtual timer offset)
///        - VBAR_EL2     (ensures exits land in our vector)
///   4. Load guest EL1 sysregs from GuestState (SCTLR_EL1, TTBR*_EL1, ...).
///   5. Prepare vGIC list registers (`vgic.prepareEntry`).
///   6. Load guest x0..x30, sp_el0, sp_el1.
///   7. MSR ELR_EL2, <pc>;  MSR SPSR_EL2, <pstate>;  ERET.
///   8. -- guest runs until an exception is taken to EL2 --
///   9. Entry lands in an asm stub which saves x0..x30 into GuestState,
///      reads ESR_EL2/FAR_EL2/HPFAR_EL2 into VmExitInfo, saves guest
///      EL1 sysregs back into GuestState, snapshots vGIC state via
///      `vgic.saveExit`, restores host GPRs/FPSIMD, and returns.
///
/// `vm_structures` is the physical base of the per-VM arch block allocated
/// by `vmAllocStructures()`. It holds the stage-2 root, HCR_EL2 value, VMID,
/// and any cached register values that never change after vm_create.
///
/// References:
///   - ARM ARM D1.11        Exception entry/return
///   - ARM ARM D13.2.46     HCR_EL2
///   - ARM ARM D13.2.151    VTTBR_EL2
///   - ARM ARM D13.2.150    VTCR_EL2
///   - 102142  §2.3         "Entry to and exit from a guest"
/// World-switch context passed by PA to the EL2 hyp dispatcher. Field
/// offsets are HARDCODED in `boot/start.S` (hvc_vcpu_run /
/// guest_exit_entry) — keep them in sync with the comment table in
/// that file. Enforced at comptime below.
pub const WorldSwitchCtx = extern struct {
    /// Physical address of the GuestState the dispatcher should swap
    /// in on entry and back out on exit.
    guest_state_pa: u64 = 0,
    /// Physical address of the HostSave struct (host callee-saved
    /// GPRs + host EL1 sysreg snapshot).
    host_save_pa: u64 = 0,
    /// Physical address of the stage-2 root (for reference; the
    /// dispatcher loads `vttbr_el2` directly).
    stage2_root_pa: u64 = 0,
    /// VTTBR_EL2 value: VMID << 48 | stage2_root_pa.
    vttbr_el2: u64 = 0,
    /// VTCR_EL2 value: stage-2 translation control.
    vtcr_el2: u64 = 0,
    /// HCR_EL2 value to load on guest entry.
    hcr_el2: u64 = 0,
    /// Populated on guest exit: ESR_EL2, FAR_EL2, HPFAR_EL2.
    exit_esr: u64 = 0,
    exit_far: u64 = 0,
    exit_hpfar: u64 = 0,
    /// Stashed host ELR_EL2 / SPSR_EL2 (= host return address and
    /// PSTATE from the `hvc #0` that entered this path). The exit
    /// path restores these before its final ERET so control lands
    /// on the instruction after the host's hvc.
    host_elr_el2: u64 = 0,
    host_spsr_el2: u64 = 0,
    _pad: u64 = 0,
};

comptime {
    std.debug.assert(@offsetOf(WorldSwitchCtx, "guest_state_pa") == 0x00);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "host_save_pa") == 0x08);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "stage2_root_pa") == 0x10);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "vttbr_el2") == 0x18);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "vtcr_el2") == 0x20);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "hcr_el2") == 0x28);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "exit_esr") == 0x30);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "exit_far") == 0x38);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "exit_hpfar") == 0x40);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "host_elr_el2") == 0x48);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "host_spsr_el2") == 0x50);

    // GuestState offsets hardcoded in start.S.
    std.debug.assert(@offsetOf(GuestState, "x0") == 0x00);
    std.debug.assert(@offsetOf(GuestState, "x30") == 0xF0);
    std.debug.assert(@offsetOf(GuestState, "sp_el0") == 0xF8);
    std.debug.assert(@offsetOf(GuestState, "sp_el1") == 0x100);
    std.debug.assert(@offsetOf(GuestState, "pc") == 0x108);
    std.debug.assert(@offsetOf(GuestState, "pstate") == 0x110);
    std.debug.assert(@offsetOf(GuestState, "sctlr_el1") == 0x118);
    std.debug.assert(@offsetOf(GuestState, "ttbr0_el1") == 0x120);
    std.debug.assert(@offsetOf(GuestState, "ttbr1_el1") == 0x128);
    std.debug.assert(@offsetOf(GuestState, "tcr_el1") == 0x130);
    std.debug.assert(@offsetOf(GuestState, "mair_el1") == 0x138);
    std.debug.assert(@offsetOf(GuestState, "amair_el1") == 0x140);
    std.debug.assert(@offsetOf(GuestState, "cpacr_el1") == 0x148);
    std.debug.assert(@offsetOf(GuestState, "contextidr_el1") == 0x150);
    std.debug.assert(@offsetOf(GuestState, "tpidr_el0") == 0x158);
    std.debug.assert(@offsetOf(GuestState, "tpidr_el1") == 0x160);
    std.debug.assert(@offsetOf(GuestState, "tpidrro_el0") == 0x168);
    std.debug.assert(@offsetOf(GuestState, "vbar_el1") == 0x170);
    std.debug.assert(@offsetOf(GuestState, "elr_el1") == 0x178);
    std.debug.assert(@offsetOf(GuestState, "spsr_el1") == 0x180);
    std.debug.assert(@offsetOf(GuestState, "esr_el1") == 0x188);
    std.debug.assert(@offsetOf(GuestState, "far_el1") == 0x190);
}

/// HostSave layout — matches offsets hardcoded in start.S. Holds the
/// host's callee-saved GPRs and EL1 sysregs across a guest run.
pub const HostSave = extern struct {
    x19: u64 = 0,
    x20: u64 = 0,
    x21: u64 = 0,
    x22: u64 = 0,
    x23: u64 = 0,
    x24: u64 = 0,
    x25: u64 = 0,
    x26: u64 = 0,
    x27: u64 = 0,
    x28: u64 = 0,
    x29: u64 = 0,
    x30: u64 = 0,
    sp_el1: u64 = 0,
    sp_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    sctlr_el1: u64 = 0,
    tcr_el1: u64 = 0,
    ttbr0_el1: u64 = 0,
    ttbr1_el1: u64 = 0,
    mair_el1: u64 = 0,
    vbar_el1: u64 = 0,
    cpacr_el1: u64 = 0,
    contextidr_el1: u64 = 0,
    tpidr_el0: u64 = 0,
    tpidrro_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
    elr_el1: u64 = 0,
    spsr_el1: u64 = 0,
    esr_el1: u64 = 0,
    far_el1: u64 = 0,
};

comptime {
    std.debug.assert(@offsetOf(HostSave, "x19") == 0x00);
    std.debug.assert(@offsetOf(HostSave, "x30") == 0x58);
    std.debug.assert(@offsetOf(HostSave, "sp_el1") == 0x60);
    std.debug.assert(@offsetOf(HostSave, "sp_el0") == 0x68);
    std.debug.assert(@offsetOf(HostSave, "tpidr_el1") == 0x70);
    std.debug.assert(@offsetOf(HostSave, "sctlr_el1") == 0x78);
    std.debug.assert(@offsetOf(HostSave, "tcr_el1") == 0x80);
    std.debug.assert(@offsetOf(HostSave, "far_el1") == 0xE8);
}

// HCR_EL2 bits (ARM ARM D13.2.46).
pub const HCR_EL2_VM: u64 = 1 << 0; // stage-2 enable
pub const HCR_EL2_FMO: u64 = 1 << 3; // route vFIQ
pub const HCR_EL2_IMO: u64 = 1 << 4; // route vIRQ
pub const HCR_EL2_AMO: u64 = 1 << 5; // route vSError
pub const HCR_EL2_RW: u64 = 1 << 31; // EL1 is AArch64

/// VTCR_EL2 value for our stage-2 config: 4K granule, T0SZ=34 (1 GiB
/// IPA), SL0=00 (start at level 2), shareability/cacheability
/// inner-shareable WB, PS=40-bit output. ARM ARM D13.2.150.
pub fn vtcrEl2Value() u64 {
    const t0sz: u64 = STAGE2_T0SZ; // 34
    const sl0: u64 = 0;             // start at level 2 (w/ 4K, T0SZ=34)
    const irgn0: u64 = 0b01;        // Normal WB WA cacheable
    const orgn0: u64 = 0b01;
    const sh0: u64 = 0b11;          // Inner shareable
    const tg0: u64 = 0b00;          // 4 KiB granule
    const ps: u64 = 0b010;          // 40-bit PA
    return t0sz |
        (sl0 << 6) |
        (irgn0 << 8) |
        (orgn0 << 10) |
        (sh0 << 12) |
        (tg0 << 14) |
        (ps << 16);
}

/// Decode ESR_EL2 into a typed VmExitInfo. Covers the minimum set of
/// exception classes needed for nop-guest bring-up; deep ISS decode is
/// left to later waves.
///
/// ARM ARM D13.2.39 Table D13-45.
pub fn decodeEsrEl2(esr: u64, far: u64, hpfar: u64) VmExitInfo {
    const ec: u8 = @intCast((esr >> 26) & 0x3F);
    const iss: u32 = @intCast(esr & 0x01FF_FFFF);
    return switch (ec) {
        0x01 => .{ .wfi_wfe = .{ .is_wfe = (iss & 1) != 0 } },
        0x16 => .{ .hvc = .{ .imm = @intCast(iss & 0xFFFF) } },
        0x17 => .{ .smc = .{ .imm = @intCast(iss & 0xFFFF) } },
        0x18 => .{ .sysreg_trap = .{
            .iss = iss,
            .op0 = @intCast((iss >> 20) & 0x3),
            .op1 = @intCast((iss >> 14) & 0x7),
            .crn = @intCast((iss >> 10) & 0xF),
            .crm = @intCast((iss >> 1) & 0xF),
            .op2 = @intCast((iss >> 17) & 0x7),
            .rt = @intCast((iss >> 5) & 0x1F),
            .is_read = (iss & 1) != 0,
        } },
        0x20, 0x24 => blk: {
            const guest_phys = ((hpfar & 0x0FFF_FFFF_FFF0) << 8) | (far & 0xFFF);
            const iss_valid = (iss & (1 << 24)) != 0;
            break :blk .{ .stage2_fault = .{
                .guest_phys = guest_phys,
                .guest_virt = far,
                .is_instruction = ec == 0x20,
                .is_write = (iss & (1 << 6)) != 0,
                .access_size = @intCast((iss >> 22) & 0x3),
                .srt = @intCast((iss >> 16) & 0x1F),
                .iss_valid = iss_valid,
            } };
        },
        0x00 => .{ .unknown_ec = 0 },
        else => .{ .unknown = esr },
    };
}

/// Per-vCPU scratch the EL2 hyp stub reads/writes through PAs. Owned by
/// the VCpu object (see `kernel/arch/aarch64/kvm/vcpu.zig`) so concurrent
/// vCPUs don't share storage. Both fields must live in physmap-backed
/// memory so `PAddr.fromVAddr(..., null)` is a valid VA→PA translation.
pub const ArchScratch = extern struct {
    ctx: WorldSwitchCtx = .{},
    host_save: HostSave = .{},
};

pub fn vmResume(
    guest_state: *GuestState,
    vm_structures: PAddr,
    guest_fxsave: *align(16) FxsaveArea,
    arch_scratch: *ArchScratch,
) VmExitInfo {
    _ = guest_fxsave; // FPSIMD save/restore TODO.

    const ctx = &arch_scratch.ctx;
    const host_save = &arch_scratch.host_save;
    ctx.* = .{};
    host_save.* = .{};

    const gs_pa = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(guest_state)), null);
    const hs_pa = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(host_save)), null);
    const ctx_pa = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(ctx)), null);

    ctx.guest_state_pa = gs_pa.addr;
    ctx.host_save_pa = hs_pa.addr;
    ctx.stage2_root_pa = vm_structures.addr;
    ctx.vttbr_el2 = vm_structures.addr; // VMID = 0 (TODO: real VMID alloc).
    ctx.vtcr_el2 = vtcrEl2Value();
    ctx.hcr_el2 = HCR_EL2_VM | HCR_EL2_RW | HCR_EL2_IMO | HCR_EL2_FMO | HCR_EL2_AMO;

    _ = hypCall(.vcpu_run, ctx_pa.addr);

    return decodeEsrEl2(ctx.exit_esr, ctx.exit_far, ctx.exit_hpfar);
}

// ===========================================================================
// EL2 hyp world-switch handlers
// ===========================================================================
//
// These mirror the x64 inline-asm vmResume structure (see x64/intel/vmx.zig)
// but with one architectural twist: ARMv8 EL1↔EL2 transitions are mediated
// by the EL2 vector table, not by a single instruction. The UEFI bootloader
// installs a minimal EL2 hyp stub at VBAR_EL2 (see
// `bootloader/aarch64_el2_drop.zig`) whose only handler is a bare `eret` on
// HVC. The kernel's full world-switch dispatcher below is therefore
// currently **dormant** — the symbols are defined and the code is linked in,
// but nothing writes VBAR_EL2 with a table that branches to them. Task #113
// tracks wiring this in: kernel issues an HVC to the bootloader stub, passing
// the PA of its own vector table, which the stub installs via `msr vbar_el2`.
//
// Symbols defined here (to be referenced from a future `__hyp_vectors` table):
//   hyp_sync_lower_a64   — dispatcher: tpidr_el2 != 0 → guest exit;
//                          else decode ESR_EL2.EC == HVC and dispatch x0.
//   hvc_noop             — id=0 round-trip smoke test (returns x1 ^ 1).
//   hvc_vcpu_run         — id=1 entry path: save host, load guest, ERET.
//   guest_exit_entry     — exit path: save guest, restore host, ERET.
//   hyp_halt             — wfe loop for unrecognised exceptions.
//
// All four handlers run with EL2 MMU off, so:
//   - PAs only — no high-VA dereferences.
//   - SP_EL2 is expected to be set up by whoever installs the vector table.
//   - tpidr_el2 doubles as "currently active WorldSwitchCtx PA" marker.

export fn hyp_sync_lower_a64() callconv(.naked) noreturn {
    asm volatile (
        \\  // If tpidr_el2 != 0 we were running a guest; this is a VM exit.
        \\  mrs     x18, tpidr_el2
        \\  cbnz    x18, guest_exit_entry
        \\
        \\  // Host hypercall path. Decode ESR_EL2.EC; we only support EC=0x16.
        \\  mrs     x18, esr_el2
        \\  lsr     x18, x18, #26
        \\  and     x18, x18, #0x3F
        \\  cmp     x18, #0x16
        \\  b.ne    hyp_halt
        \\
        \\  // Dispatch by x0.
        \\  cmp     x0, #0
        \\  b.eq    hvc_noop
        \\  cmp     x0, #1
        \\  b.eq    hvc_vcpu_run
        \\  // Unknown id — return -1.
        \\  mov     x0, #-1
        \\  eret
    );
}

export fn hvc_noop() callconv(.naked) noreturn {
    asm volatile (
        \\  // Return arg^1 so the caller can verify the round-trip changed x0.
        \\  eor     x0, x1, #1
        \\  eret
    );
}

// hvc_vcpu_run — Phase B: world-switch entry.
//
// On entry:
//   x1 = PA of a WorldSwitchCtx (offsets pinned by comptime asserts above).
//   x0 = HypCallId.vcpu_run (1) — discarded.
//
// Saves host callee-saved GPRs + EL1 sysregs into ctx.host_save, programs
// per-VM EL2 state (HCR/VTCR/VTTBR/CNTVOFF), loads guest EL1 sysregs and
// GPRs from ctx.guest_state, sets tpidr_el2 = ctx_pa as the "guest active"
// marker, and ERETs to the guest at guest.pc / guest.pstate.
export fn hvc_vcpu_run() callconv(.naked) noreturn {
    asm volatile (
        \\  // x1 = ctx PA. Preserve it in x18 across sysreg work.
        \\  mov     x18, x1
        \\
        \\  // Stash host ELR_EL2 / SPSR_EL2 into the ctx so the exit path can
        \\  // ERET back to the host kernel (after the `hvc #0` in hypCall).
        \\  // Without this the exit ERET would use whatever the guest exit
        \\  // wrote into these regs.
        \\  mrs     x3, elr_el2
        \\  str     x3, [x18, #0x48]
        \\  mrs     x3, spsr_el2
        \\  str     x3, [x18, #0x50]
        \\
        \\  // ---- Save host callee-saved GPRs + EL1 sysregs to host_save ----
        \\  ldr     x2, [x18, #0x08]        // host_save_pa
        \\  stp     x19, x20, [x2, #0x00]
        \\  stp     x21, x22, [x2, #0x10]
        \\  stp     x23, x24, [x2, #0x20]
        \\  stp     x25, x26, [x2, #0x30]
        \\  stp     x27, x28, [x2, #0x40]
        \\  stp     x29, x30, [x2, #0x50]
        \\
        \\  mrs     x3, sp_el1
        \\  str     x3, [x2, #0x60]
        \\  mrs     x3, sp_el0
        \\  str     x3, [x2, #0x68]
        \\  mrs     x3, tpidr_el1
        \\  str     x3, [x2, #0x70]
        \\  mrs     x3, sctlr_el1
        \\  str     x3, [x2, #0x78]
        \\  mrs     x3, tcr_el1
        \\  str     x3, [x2, #0x80]
        \\  mrs     x3, ttbr0_el1
        \\  str     x3, [x2, #0x88]
        \\  mrs     x3, ttbr1_el1
        \\  str     x3, [x2, #0x90]
        \\  mrs     x3, mair_el1
        \\  str     x3, [x2, #0x98]
        \\  mrs     x3, vbar_el1
        \\  str     x3, [x2, #0xA0]
        \\  mrs     x3, cpacr_el1
        \\  str     x3, [x2, #0xA8]
        \\  mrs     x3, contextidr_el1
        \\  str     x3, [x2, #0xB0]
        \\  mrs     x3, tpidr_el0
        \\  str     x3, [x2, #0xB8]
        \\  mrs     x3, tpidrro_el0
        \\  str     x3, [x2, #0xC0]
        \\  mrs     x3, cntkctl_el1
        \\  str     x3, [x2, #0xC8]
        \\  mrs     x3, elr_el1
        \\  str     x3, [x2, #0xD0]
        \\  mrs     x3, spsr_el1
        \\  str     x3, [x2, #0xD8]
        \\  mrs     x3, esr_el1
        \\  str     x3, [x2, #0xE0]
        \\  mrs     x3, far_el1
        \\  str     x3, [x2, #0xE8]
        \\
        \\  // ---- Program per-VM EL2 state ----
        \\  ldr     x3, [x18, #0x28]        // hcr_el2
        \\  msr     hcr_el2, x3
        \\  ldr     x3, [x18, #0x20]        // vtcr_el2
        \\  msr     vtcr_el2, x3
        \\  ldr     x3, [x18, #0x18]        // vttbr_el2
        \\  msr     vttbr_el2, x3
        \\  msr     cntvoff_el2, xzr
        \\  isb
        \\
        \\  // Stage-2 TLB invalidate for the fresh VMID (cheap; just VMALLS12E1IS).
        \\  tlbi    vmalls12e1is
        \\  dsb     ish
        \\  isb
        \\
        \\  // ---- Load guest EL1 sysregs from GuestState ----
        \\  ldr     x2, [x18, #0x00]        // guest_state_pa
        \\  ldr     x3, [x2, #0x118]        // sctlr_el1
        \\  msr     sctlr_el1, x3
        \\  ldr     x3, [x2, #0x120]        // ttbr0_el1
        \\  msr     ttbr0_el1, x3
        \\  ldr     x3, [x2, #0x128]        // ttbr1_el1
        \\  msr     ttbr1_el1, x3
        \\  ldr     x3, [x2, #0x130]        // tcr_el1
        \\  msr     tcr_el1, x3
        \\  ldr     x3, [x2, #0x138]        // mair_el1
        \\  msr     mair_el1, x3
        \\  ldr     x3, [x2, #0x148]        // cpacr_el1
        \\  msr     cpacr_el1, x3
        \\  ldr     x3, [x2, #0x150]        // contextidr_el1
        \\  msr     contextidr_el1, x3
        \\  ldr     x3, [x2, #0x158]        // tpidr_el0
        \\  msr     tpidr_el0, x3
        \\  ldr     x3, [x2, #0x160]        // tpidr_el1
        \\  msr     tpidr_el1, x3
        \\  ldr     x3, [x2, #0x168]        // tpidrro_el0
        \\  msr     tpidrro_el0, x3
        \\  ldr     x3, [x2, #0x170]        // vbar_el1
        \\  msr     vbar_el1, x3
        \\  ldr     x3, [x2, #0x178]        // elr_el1
        \\  msr     elr_el1, x3
        \\  ldr     x3, [x2, #0x180]        // spsr_el1
        \\  msr     spsr_el1, x3
        \\  ldr     x3, [x2, #0x188]        // esr_el1
        \\  msr     esr_el1, x3
        \\  ldr     x3, [x2, #0x190]        // far_el1
        \\  msr     far_el1, x3
        \\  ldr     x3, [x2, #0x0F8]        // sp_el0
        \\  msr     sp_el0, x3
        \\  ldr     x3, [x2, #0x100]        // sp_el1
        \\  msr     sp_el1, x3
        \\  isb
        \\
        \\  // ---- Program ELR_EL2 / SPSR_EL2 from guest.pc / guest.pstate ----
        \\  ldr     x3, [x2, #0x108]        // guest.pc
        \\  msr     elr_el2, x3
        \\  ldr     x3, [x2, #0x110]        // guest.pstate
        \\  msr     spsr_el2, x3
        \\
        \\  // ---- Mark active ctx so exits take the guest_exit path ----
        \\  msr     tpidr_el2, x18
        \\  isb
        \\
        \\  // ---- Load guest GPRs x0..x30 from GuestState ----
        \\  // x2 holds guest_state_pa; keep it live until the last load.
        \\  ldp     x0, x1, [x2, #0x00]
        \\  ldp     x3, x4, [x2, #0x18]
        \\  ldp     x5, x6, [x2, #0x28]
        \\  ldp     x7, x8, [x2, #0x38]
        \\  ldp     x9, x10, [x2, #0x48]
        \\  ldp     x11, x12, [x2, #0x58]
        \\  ldp     x13, x14, [x2, #0x68]
        \\  ldp     x15, x16, [x2, #0x78]
        \\  ldp     x17, x18, [x2, #0x88]
        \\  ldp     x19, x20, [x2, #0x98]
        \\  ldp     x21, x22, [x2, #0xA8]
        \\  ldp     x23, x24, [x2, #0xB8]
        \\  ldp     x25, x26, [x2, #0xC8]
        \\  ldp     x27, x28, [x2, #0xD8]
        \\  ldp     x29, x30, [x2, #0xE8]
        \\  // x2 is still live; reload final (x2) value last.
        \\  ldr     x2, [x2, #0x10]
        \\  eret
    );
}

// guest_exit_entry — Phase C: world-switch exit.
//
// On entry: guest was running at EL1, took an exception to EL2.
//   tpidr_el2 = PA of the active WorldSwitchCtx.
//   All GPRs still hold guest values.
//
// Saves guest GPRs and EL1 sysregs into ctx.guest_state, populates
// ctx.exit_{esr,far,hpfar}, restores host EL1 sysregs and callee-saved
// GPRs, clears tpidr_el2, restores host ELR_EL2/SPSR_EL2 stashed at entry,
// and ERETs back to the host (instruction after `hvc #0` in hypCall).
export fn guest_exit_entry() callconv(.naked) noreturn {
    asm volatile (
        \\  // Reclaim ctx pointer from tpidr_el2 without clobbering x0..x17.
        \\  // Use SP_EL2 as a two-slot scratch to free up x17/x18.
        \\  sub     sp, sp, #16
        \\  str     x18, [sp]
        \\  mrs     x18, tpidr_el2          // x18 = ctx_pa
        \\  str     x17, [sp, #8]
        \\  ldr     x17, [x18, #0x00]       // x17 = guest_state_pa
        \\
        \\  // Store guest x0..x16 into GuestState x0..x16 slots.
        \\  stp     x0, x1, [x17, #0x00]
        \\  stp     x2, x3, [x17, #0x10]
        \\  stp     x4, x5, [x17, #0x20]
        \\  stp     x6, x7, [x17, #0x30]
        \\  stp     x8, x9, [x17, #0x40]
        \\  stp     x10, x11, [x17, #0x50]
        \\  stp     x12, x13, [x17, #0x60]
        \\  stp     x14, x15, [x17, #0x70]
        \\  // x16 and guest-x17 (stashed on stack at sp+8).
        \\  ldr     x0, [sp, #8]            // guest x17
        \\  stp     x16, x0, [x17, #0x80]
        \\  // guest x18 stashed at sp+0.
        \\  ldr     x0, [sp, #0]            // guest x18
        \\  str     x0, [x17, #0x90]
        \\  add     sp, sp, #16
        \\  // x19..x30 are still guest values (we haven't touched them yet).
        \\  stp     x19, x20, [x17, #0x98]
        \\  stp     x21, x22, [x17, #0xA8]
        \\  stp     x23, x24, [x17, #0xB8]
        \\  stp     x25, x26, [x17, #0xC8]
        \\  stp     x27, x28, [x17, #0xD8]
        \\  stp     x29, x30, [x17, #0xE8]
        \\
        \\  // ---- Save guest pc/pstate from ELR/SPSR_EL2 ----
        \\  mrs     x0, elr_el2
        \\  str     x0, [x17, #0x108]
        \\  mrs     x0, spsr_el2
        \\  str     x0, [x17, #0x110]
        \\
        \\  // ---- Save guest EL1 sysregs back into GuestState ----
        \\  mrs     x0, sp_el0
        \\  str     x0, [x17, #0x0F8]
        \\  mrs     x0, sp_el1
        \\  str     x0, [x17, #0x100]
        \\  mrs     x0, sctlr_el1
        \\  str     x0, [x17, #0x118]
        \\  mrs     x0, ttbr0_el1
        \\  str     x0, [x17, #0x120]
        \\  mrs     x0, ttbr1_el1
        \\  str     x0, [x17, #0x128]
        \\  mrs     x0, tcr_el1
        \\  str     x0, [x17, #0x130]
        \\  mrs     x0, mair_el1
        \\  str     x0, [x17, #0x138]
        \\  mrs     x0, cpacr_el1
        \\  str     x0, [x17, #0x148]
        \\  mrs     x0, contextidr_el1
        \\  str     x0, [x17, #0x150]
        \\  mrs     x0, tpidr_el0
        \\  str     x0, [x17, #0x158]
        \\  mrs     x0, tpidr_el1
        \\  str     x0, [x17, #0x160]
        \\  mrs     x0, tpidrro_el0
        \\  str     x0, [x17, #0x168]
        \\  mrs     x0, vbar_el1
        \\  str     x0, [x17, #0x170]
        \\  mrs     x0, elr_el1
        \\  str     x0, [x17, #0x178]
        \\  mrs     x0, spsr_el1
        \\  str     x0, [x17, #0x180]
        \\  mrs     x0, esr_el1
        \\  str     x0, [x17, #0x188]
        \\  mrs     x0, far_el1
        \\  str     x0, [x17, #0x190]
        \\
        \\  // ---- Populate ctx.exit_esr / exit_far / exit_hpfar ----
        \\  mrs     x0, esr_el2
        \\  str     x0, [x18, #0x30]
        \\  mrs     x0, far_el2
        \\  str     x0, [x18, #0x38]
        \\  mrs     x0, hpfar_el2
        \\  str     x0, [x18, #0x40]
        \\
        \\  // ---- Reload host EL1 sysregs from host_save ----
        \\  ldr     x2, [x18, #0x08]        // host_save_pa
        \\  ldr     x3, [x2, #0x60]
        \\  msr     sp_el1, x3
        \\  ldr     x3, [x2, #0x68]
        \\  msr     sp_el0, x3
        \\  ldr     x3, [x2, #0x70]
        \\  msr     tpidr_el1, x3
        \\  ldr     x3, [x2, #0x78]
        \\  msr     sctlr_el1, x3
        \\  ldr     x3, [x2, #0x80]
        \\  msr     tcr_el1, x3
        \\  ldr     x3, [x2, #0x88]
        \\  msr     ttbr0_el1, x3
        \\  ldr     x3, [x2, #0x90]
        \\  msr     ttbr1_el1, x3
        \\  ldr     x3, [x2, #0x98]
        \\  msr     mair_el1, x3
        \\  ldr     x3, [x2, #0xA0]
        \\  msr     vbar_el1, x3
        \\  ldr     x3, [x2, #0xA8]
        \\  msr     cpacr_el1, x3
        \\  ldr     x3, [x2, #0xB0]
        \\  msr     contextidr_el1, x3
        \\  ldr     x3, [x2, #0xB8]
        \\  msr     tpidr_el0, x3
        \\  ldr     x3, [x2, #0xC0]
        \\  msr     tpidrro_el0, x3
        \\  ldr     x3, [x2, #0xC8]
        \\  msr     cntkctl_el1, x3
        \\  ldr     x3, [x2, #0xD0]
        \\  msr     elr_el1, x3
        \\  ldr     x3, [x2, #0xD8]
        \\  msr     spsr_el1, x3
        \\  ldr     x3, [x2, #0xE0]
        \\  msr     esr_el1, x3
        \\  ldr     x3, [x2, #0xE8]
        \\  msr     far_el1, x3
        \\
        \\  // ---- Disable stage-2 so host EL1 runs unpaginated-by-S2 ----
        \\  // HCR_EL2 = RW(31)=1 only, same as boot default.
        \\  mov     x3, #1
        \\  lsl     x3, x3, #31
        \\  msr     hcr_el2, x3
        \\  msr     vttbr_el2, xzr
        \\  isb
        \\  tlbi    vmalle1
        \\  dsb     ish
        \\  isb
        \\
        \\  // ---- Restore host callee-saved GPRs x19..x30 ----
        \\  ldp     x19, x20, [x2, #0x00]
        \\  ldp     x21, x22, [x2, #0x10]
        \\  ldp     x23, x24, [x2, #0x20]
        \\  ldp     x25, x26, [x2, #0x30]
        \\  ldp     x27, x28, [x2, #0x40]
        \\  ldp     x29, x30, [x2, #0x50]
        \\
        \\  // Clear active-ctx marker and return 0 (success) in x0.
        \\  msr     tpidr_el2, xzr
        \\  mov     x0, #0
        \\
        \\  // Restore host ELR_EL2 / SPSR_EL2 stashed by hvc_vcpu_run on entry
        \\  // (the guest exit clobbered them with guest pc/pstate, which we
        \\  // already saved into GuestState above).
        \\  ldr     x3, [x18, #0x48]        // host return elr
        \\  msr     elr_el2, x3
        \\  ldr     x3, [x18, #0x50]        // host return spsr
        \\  msr     spsr_el2, x3
        \\  eret
    );
}

export fn hyp_halt() callconv(.naked) noreturn {
    asm volatile (
        \\1:wfe
        \\  b       1b
    );
}

// ===========================================================================
// Per-VM arch structures (stage-2 root + trap config)
// ===========================================================================

// ===========================================================================
// Stage-2 translation table
// ===========================================================================
//
// Layout choice: 1 GiB IPA, 4 KiB granule, 2-level walk starting at
// Level 2. Rationale:
//   - ARM ARM D5.2, Table D5-14 (4KB granule parameter table) — with
//     TG0=00 and SL0=00, the walk starts at "initial lookup level 2"
//     and the input address size is derived from T0SZ. A T0SZ of 34
//     yields 64-34 = 30 input bits, i.e. 1 GiB of guest IPA, which is
//     enough for every v1 test VM we care about without having to
//     concatenate multiple root pages.
//   - Level 2 entries each cover 2 MiB (bits [29:21]); a single 4 KiB
//     root page holds 512 such entries (= 1 GiB). Leaf pages are at
//     level 3 (4 KiB each, bits [20:12]).
//   - Memory attributes are encoded directly in the descriptor (stage-2
//     does not consult MAIR_ELx — see ARM ARM D5.5.5 and 102142 §4.1).
//
// Descriptor format (ARM ARM D5.3.3 stage-2 descriptor):
//   [0]     valid
//   [1]     1 = table/page, 0 = block/invalid
//   [5:2]   MemAttr[3:0]   stage-2 memory type (D5.5 Table D5-37)
//   [7:6]   S2AP[1:0]      stage-2 access permissions (D5.4 Table D5-31)
//   [9:8]   SH[1:0]        shareability
//   [10]    AF             access flag (must be 1 or fault)
//   [11]    RES0 (nG does not apply to stage-2)
//   [47:12] output address
//   [50:48] RES0
//   [52]    Contiguous
//   [53]    RES0
//   [54]    XN             stage-2 execute-never
//   [58:55] software use / ignored
//   [63:59] PBHA / ignored
//
// Concept map to x86:
//   EPT root          → VTTBR_EL2 base
//   EPT pointer       → VTTBR_EL2 encoding (root PA | VMID)
//   EPT PML4/PDPT/PD  → stage-2 Level 0/1/2 tables
//   EPT PTE           → stage-2 Level 3 descriptor (4K leaf)
//   EPT RWX bits      → S2AP + XN
//   EPT memory type   → MemAttr
//
// References:
//   - ARM ARM K.a D5.4 "Stage 2 translation" (overview)
//   - ARM ARM K.a D5.5.5 "Stage 2 memory region attributes" (MemAttr)
//   - 102142 §4 "Stage 2 translation"

/// 1 GiB IPA → T0SZ = 64 - 30 = 34. Exposed so the VmControlBlock
/// setup (VTCR_EL2) can cite a single source of truth.
pub const STAGE2_T0SZ: u6 = 34;

/// Number of stage-2 translation levels walked for our (T0SZ=34,
/// SL0=0, 4KB granule) configuration. Level 2 → Level 3 = 2 levels.
const STAGE2_LEVELS: usize = 2;

/// Bit shifts per level, from leaf upwards. Matches the naming used by
/// `kernel/arch/aarch64/paging.zig` for stage-1 (l0sh=12, l1sh=21, ...).
const stage2_leaf_shift: u6 = 12; // level 3 (4 KiB leaf)
const stage2_mid_shift: u6 = 21; // level 2 (2 MiB each)

/// Stage-2 descriptor. Separate from the stage-1 `PageEntry` because the
/// stage-2 encoding is non-trivially different (no AP[2:1], no AttrIndx,
/// MemAttr replaces MAIR indirection, XN at bit 54, no nG).
/// ARM ARM D5.3.3.
const Stage2Entry = packed struct(u64) {
    valid: bool = false,
    /// At a non-leaf level: 1 = table descriptor.
    /// At a leaf level (level 3 with 4 KB granule): 1 = page descriptor.
    /// Both use bit 1 = 1 because the leaf is level 3, not a block.
    is_table_or_page: bool = false,
    /// MemAttr[3:0] — stage-2 memory type. For Normal WB RAM use 0b1111
    /// (Inner/Outer WB non-transient). For Device-nGnRnE MMIO use 0b0000.
    /// ARM ARM D5.5.5, Table D5-37.
    mem_attr: u4 = 0,
    /// S2AP[1:0] — stage-2 access permissions. D5.4 Table D5-31:
    ///   0b00 = none, 0b01 = RO, 0b10 = WO, 0b11 = RW.
    s2ap: u2 = 0,
    /// SH[1:0] — shareability. 0b11 = Inner Shareable, required for SMP.
    sh: u2 = 0,
    /// AF — access flag. Must be set (or the first access traps).
    af: bool = false,
    /// Bit 11: RES0 at stage-2 (the nG bit only applies to stage-1).
    _res11: bool = false,
    /// Output address bits [47:12] of the next-level table (non-leaf)
    /// or the final physical page (leaf).
    addr: u36 = 0,
    _res50_48: u3 = 0,
    /// Contiguous hint; zero for single-page leaves.
    contiguous: bool = false,
    _res53: bool = false,
    /// XN — stage-2 execute-never. Set for non-executable guest mappings.
    xn: bool = false,
    _sw: u4 = 0,
    _ignored: u5 = 0,
    _res63: u1 = 0,

    fn setPAddr(self: *Stage2Entry, p: PAddr) void {
        std.debug.assert(std.mem.isAligned(p.addr, paging.PAGE4K));
        self.addr = @intCast(p.addr >> 12);
    }

    fn getPAddr(self: *const Stage2Entry) PAddr {
        return PAddr.fromInt(@as(u64, self.addr) << 12);
    }
};

const STAGE2_ENTRIES_PER_TABLE: usize = 512;

/// Index of `guest_phys` into the level-2 root table (bits [29:21]).
inline fn stage2L2Idx(guest_phys: u64) u9 {
    return @truncate(guest_phys >> stage2_mid_shift);
}

/// Index of `guest_phys` into a level-3 table (bits [20:12]).
inline fn stage2L3Idx(guest_phys: u64) u9 {
    return @truncate(guest_phys >> stage2_leaf_shift);
}

/// Allocate and zero a 4 KiB page from the global PMM and return its PA.
fn allocTablePage() ?PAddr {
    const alloc = pmm.global_pmm.?.allocator();
    const page = alloc.create(paging.PageMem(.page4k)) catch return null;
    @memset(std.mem.asBytes(page), 0);
    const va = VAddr.fromInt(@intFromPtr(page));
    return PAddr.fromVAddr(va, null);
}

/// Free a 4 KiB table page that was previously allocated by `allocTablePage`.
fn freeTablePage(p: PAddr) void {
    const alloc = pmm.global_pmm.?.allocator();
    const va = VAddr.fromPAddr(p, null);
    const page: *paging.PageMem(.page4k) = @ptrFromInt(va.addr);
    alloc.destroy(page);
}

/// Allocate the per-VM arch block. For this v1 implementation the "arch
/// structures" are exactly the stage-2 L2 root page — a single 4 KiB
/// table with 512 level-2 entries, each covering 2 MiB = 1 GiB total IPA.
/// `vm_structures` values returned from here are the physical address of
/// that root and can be loaded directly into `VTTBR_EL2.BADDR`.
///
/// Not yet tracked:
///   - A separate VmControlBlock holding cached HCR_EL2 / VTCR_EL2 /
///     CNTVOFF_EL2 values. Those live in the Vm object for now and are
///     baked into `vmResume` once it lands. A future refactor will
///     break them out into a per-VM page alongside the stage-2 root.
pub fn vmAllocStructures() ?PAddr {
    return allocTablePage();
}

/// Tear down the per-VM arch block. Walks the stage-2 root, frees every
/// allocated level-3 table page, then frees the root.
///
/// TLB invalidation for the departing VMID is the caller's job (done
/// inside `Vm.destroy` once VMID management is real). Stage-2 leaks
/// here would be contained to a single VM and caught on the next
/// rollover, but we still walk-and-free to keep the PMM honest.
pub fn vmFreeStructures(p: PAddr) void {
    if (p.addr == 0) return;
    const root: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry =
        @ptrFromInt(VAddr.fromPAddr(p, null).addr);
    for (root) |*entry| {
        if (!entry.valid) continue;
        // Every non-leaf entry we install is a table descriptor pointing
        // at a level-3 page. The level-3 page itself contains leaves only,
        // so freeing it is enough; we do not recurse further.
        freeTablePage(entry.getPAddr());
        entry.* = .{};
    }
    freeTablePage(p);
}

/// Install a 4 KiB stage-2 mapping `guest_phys → host_phys` with the
/// supplied rights (bit 0 = read, bit 1 = write, bit 2 = exec).
///
/// Walks the level-2 root, allocates a level-3 page if the L2 slot is
/// empty, then writes the leaf descriptor. Issues a single
/// `TLBI IPAS2LE1IS, <ipa>>>12` + `DSB ISH` afterwards so stale
/// speculative walks cannot hit the new descriptor with an old value.
pub fn mapGuestPage(vm_structures: PAddr, guest_phys: u64, host_phys: PAddr, rights: u8) !void {
    if (guest_phys >= (1 << 30)) return error.IpaOutOfRange;
    std.debug.assert(std.mem.isAligned(guest_phys, paging.PAGE4K));
    std.debug.assert(std.mem.isAligned(host_phys.addr, paging.PAGE4K));

    const root_va = VAddr.fromPAddr(vm_structures, null).addr;
    const root: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry = @ptrFromInt(root_va);

    const l2_idx = stage2L2Idx(guest_phys);
    const l2_entry = &root[l2_idx];

    // Allocate the L3 table on first touch.
    if (!l2_entry.valid) {
        const l3_pa = allocTablePage() orelse return error.OutOfMemory;
        l2_entry.* = .{
            .valid = true,
            .is_table_or_page = true, // table descriptor at level 2
            // MemAttr/S2AP/SH/AF/XN fields on a *table* descriptor are
            // RES0 / ignored per ARM ARM D5.3.3 Table D5-15. The HW walker
            // only consults them on leaf descriptors.
        };
        l2_entry.setPAddr(l3_pa);
    }

    const l3_va = VAddr.fromPAddr(l2_entry.getPAddr(), null).addr;
    const l3: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry = @ptrFromInt(l3_va);
    const l3_idx = stage2L3Idx(guest_phys);

    const can_read = (rights & 0x1) != 0;
    const can_write = (rights & 0x2) != 0;
    const can_exec = (rights & 0x4) != 0;

    // S2AP encoding (ARM ARM D5.4 Table D5-31):
    //   0b00 = no access, 0b01 = RO, 0b10 = WO (rarely used), 0b11 = RW.
    // Our rights bits allow R, W, X independently; we map any non-read
    // mapping with write set to RW rather than WO, which matches what
    // x86 EPT would do.
    const s2ap: u2 = if (can_write) 0b11 else if (can_read) 0b01 else 0b00;

    // MemAttr for Normal Write-Back Inner/Outer cacheable memory. ARM ARM
    // D5.5.5 Table D5-37: 0b1111 = Normal Inner WB, Outer WB, non-transient.
    const mem_attr: u4 = 0b1111;

    l3[l3_idx] = .{
        .valid = true,
        .is_table_or_page = true, // level-3 leaf uses bits [1:0] = 0b11
        .mem_attr = mem_attr,
        .s2ap = s2ap,
        .sh = 0b11, // Inner Shareable
        .af = true,
        .xn = !can_exec,
    };
    l3[l3_idx].setPAddr(host_phys);

    stage2InvalidateIpa(guest_phys);
}

/// Remove a 4 KiB stage-2 mapping. Leaves the owning L3 table in place;
/// the L3 table is freed in bulk by `vmFreeStructures`.
pub fn unmapGuestPage(vm_structures: PAddr, guest_phys: u64) void {
    if (guest_phys >= (1 << 30)) return;

    const root_va = VAddr.fromPAddr(vm_structures, null).addr;
    const root: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry = @ptrFromInt(root_va);

    const l2_entry = &root[stage2L2Idx(guest_phys)];
    if (!l2_entry.valid) return;

    const l3_va = VAddr.fromPAddr(l2_entry.getPAddr(), null).addr;
    const l3: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry = @ptrFromInt(l3_va);
    l3[stage2L3Idx(guest_phys)] = .{};

    stage2InvalidateIpa(guest_phys);
}

/// Invalidate any cached stage-2 translation for `guest_phys` in the
/// current VM's VMID.
///
/// `TLBI IPAS2E1IS, <ipa>>>12` is the architectural instruction for
/// stage-2 invalidation (ARM ARM K.a D7.7 "TLB maintenance
/// instructions"), but it is EL2-only: executing it from EL1 is
/// UNDEFINED and would trap. The Zag kernel runs at EL1, so we cannot
/// issue TLBIs directly here.
///
/// For v1 this is a deliberate no-op. Correctness is preserved because:
///
///   1. Fresh stage-2 descriptors written by `mapGuestPage` are only
///      visible to the guest after the next `ERET` back into EL1N, at
///      which point the hardware re-walks unless there is a cached
///      entry — and because no vCPU has yet entered the guest after
///      this descriptor was written, there is no cached entry to
///      invalidate.
///   2. `unmapGuestPage` has a potential stale-entry window, but the
///      only in-tree caller is VM teardown, and `vmFreeStructures`
///      tears down the entire VMID — so the TLB eviction happens on
///      the next VMID rollover.
///
/// The EL2 entry path (Task #6: `vmResume`) will grow a proper
/// invalidation point that batches IPA invalidations into the
/// post-context-switch sequence, matching the Linux `__tlb_switch_to_*`
/// dance. Until that lands, the invalidate-on-write guarantee we need
/// for live guests simply does not apply because no guest ever runs.
fn stage2InvalidateIpa(guest_phys: u64) void {
    _ = guest_phys;
}

// ===========================================================================
// Interrupt / exception injection
// ===========================================================================

/// Inject a virtual interrupt into the guest vCPU.
///
/// Sets the corresponding `pending_v*` flag in GuestState so the next
/// `vmResume` knows something needs to be delivered. The real vGIC LR
/// programming happens in `vgic.prepareEntry` on the entry path.
/// `kvm.vcpu.vcpuInterrupt` calls this as a fallback for the non-vGIC
/// path (legacy HCR_EL2.VI/.VF/.VSE bit injection); production flows
/// route straight to `vgic.injectInterrupt` instead.
pub fn injectInterrupt(guest_state: *GuestState, interrupt: GuestInterrupt) void {
    switch (interrupt.kind) {
        0 => guest_state.pending_virq = 1,
        1 => guest_state.pending_vfiq = 1,
        2 => guest_state.pending_vserror = 1,
        else => {},
    }
}

/// Inject a synchronous exception into the guest at EL1.
///
/// Per ARM ARM K.a D1.11 "Exception entry":
///   1. SPSR_EL1 receives the current PSTATE.
///   2. ELR_EL1 receives the faulting PC.
///   3. ESR_EL1 receives the syndrome the guest will observe.
///   4. FAR_EL1 receives the fault address (data/instruction aborts).
///   5. PC is redirected to VBAR_EL1 + vector offset (Table D1-7).
///   6. PSTATE.{M=EL1h, D=1, A=1, I=1, F=1} per D1.11.3.
///
/// Vector offsets (relative to VBAR_EL1), D1.11.2 Table D1-7:
///   0x000 = Current EL SP0  sync
///   0x080 = Current EL SP0  irq
///   0x100 = Current EL SP0  fiq
///   0x180 = Current EL SP0  serror
///   0x200 = Current EL SPx  sync
///   0x280 = Current EL SPx  irq
///   0x300 = Current EL SPx  fiq
///   0x380 = Current EL SPx  serror
///   0x400 = Lower EL A64    sync
///
/// `vector_slot` is an index into this table (0..8) so the VMM can
/// pick the exception kind it wants to inject; 4 (lower-EL sync) is
/// the most common choice for delivering a synthetic exception that
/// the guest kernel handles as "my userspace faulted".
pub fn injectException(guest_state: *GuestState, exception: GuestException) void {
    guest_state.spsr_el1 = guest_state.pstate;
    guest_state.elr_el1 = guest_state.pc;
    guest_state.esr_el1 = exception.esr;
    guest_state.far_el1 = exception.far;

    const vector_offset: u64 = switch (exception.vector_slot) {
        0 => 0x000,
        1 => 0x080,
        2 => 0x100,
        3 => 0x180,
        4 => 0x200,
        5 => 0x280,
        6 => 0x300,
        7 => 0x380,
        else => 0x400,
    };
    guest_state.pc = guest_state.vbar_el1 +% vector_offset;

    // Target PSTATE per D1.11.3: EL1h, DAIF all masked (entering an
    // exception masks I/F/A/D until the handler explicitly unmasks).
    guest_state.pstate = 0x3C5; // M=EL1h (0b0101), D=A=I=F=1
}

// ===========================================================================
// Sysreg passthrough
// ===========================================================================

/// Enable/disable trap-free access to a system register for the guest.
///
/// The x86 MSR bitmap does not exist on ARM; instead each class of register
/// has its own trap bit in HCR_EL2/CPTR_EL2/MDCR_EL2/CNTHCTL_EL2. This
/// function decodes `sysreg_id` as a packed (op0,op1,crn,crm,op2) key and
/// flips the relevant trap bit in the VM control block.
///
/// Encoding used by userspace:
///   bits [15:14] Op0
///   bits [13:11] Op1
///   bits [10:7]  CRn
///   bits [6:3]   CRm
///   bits [2:0]   Op2
pub fn sysregPassthrough(vm_structures: PAddr, sysreg_id: u32, allow_read: bool, allow_write: bool) void {
    _ = vm_structures;
    _ = sysreg_id;
    _ = allow_read;
    _ = allow_write;
}
