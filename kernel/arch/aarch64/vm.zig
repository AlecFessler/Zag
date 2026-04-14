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

const aarch64_paging = zag.arch.aarch64.paging;
const hyp_consts = zag.arch.aarch64.hyp_consts;
const memory_init = zag.memory.init;
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
        /// Write not-read flag (ESR_EL2.ISS.WnR, data abort only).
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
        /// Sign-extended load (ISS.SSE, data abort only).
        sign_extend: bool,
        /// 64-bit register access (ISS.SF, data abort only).
        reg64: bool,
        /// Acquire/release semantics (ISS.AR, data abort only).
        acqrel: bool,
        /// Data/Instruction Fault Status Code (ISS.DFSC for EC=0x24 or
        /// ISS.IFSC for EC=0x20). Low 6 bits. See ARM ARM D13.2.39
        /// Table D13-46.
        fsc: u8,
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

/// Set to true once `installHypVectors()` has run on any core. Guards
/// secondary cores from re-issuing the install HVC: on APs we do not
/// currently control EL2 (they come up via PSCI CPU_ON without the
/// bootloader's EL2 drop sequence), so a second HVC could trap into an
/// unknown EL2 handler. Tracked as a global because all cores share the
/// same VMM toolchain state; until a dedicated per-core EL2 bringup path
/// exists, VM runs are pinned to the BSP.
/// TODO(smp): install vectors on every core once AP EL2 bringup lands.
var hyp_vectors_installed: bool = false;

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

/// Install the kernel's EL2 vector table at VBAR_EL2 via an HVC to the
/// bootloader's minimal EL2 stub.
///
/// The bootloader leaves a tiny stub table at VBAR_EL2 whose sync-lower
/// A64 handler (bootloader/aarch64_el2_drop.zig) decodes the HVC imm16
/// and, on HVC_IMM_INSTALL_VBAR_EL2, writes X0 into VBAR_EL2. That lets
/// us hand EL2 a full vector table that branches into
/// `hyp_sync_lower_a64` without needing EL2 register access from EL1.
///
/// VBAR_EL2 holds a PHYSICAL address; the naked `__hyp_vectors` symbol
/// is linked at a kernel high-half VA, so we walk the kernel page tables
/// to resolve its PA first. The table is 2 KiB aligned (ARM ARM D1.10.2
/// — VBAR_ELx bits [10:0] are RES0).
pub fn installHypVectors() void {
    // Requires both a CPU that implements EL2 and a live EL2 stub sitting
    // at VBAR_EL2 willing to honour our install HVC. On the UEFI path the
    // bootloader installs that stub in aarch64_el2_drop.zig; if we booted
    // at EL1 with no stub, there is no one to service the HVC and issuing
    // it would trap to EL1 as an undefined instruction.
    if (!vm_supported or !hyp_stub_installed) return;
    if (hyp_vectors_installed) return;

    const vec_va: u64 = @intFromPtr(&__hyp_vectors);
    const page_paddr = aarch64_paging.resolveVaddr(
        memory_init.kernel_addr_space_root,
        VAddr.fromInt(vec_va),
    ) orelse return;
    const vec_pa = page_paddr.addr | (vec_va & 0xFFF);
    std.debug.assert(vec_pa & 0x7FF == 0);

    const hvc_insn = comptime std.fmt.comptimePrint(
        "hvc #{d}",
        .{hyp_consts.HVC_IMM_INSTALL_VBAR_EL2},
    );
    asm volatile (hvc_insn
        :
        : [vbar] "{x0}" (vec_pa),
        : .{ .memory = true });

    hyp_vectors_installed = true;
}

/// Per-core VM initialization. Called from `sched.perCoreInit()` on every
/// CPU after global init. On ARM the per-core setup is small: ensure EL2
/// vectors are installed and that per-core trap configuration (HCR_EL2
/// RES1 bits, MDCR_EL2 for PMU trap sharing, etc.) reflects the boot-time
/// defaults. All real state is per-VM, so this is essentially a no-op on
/// a hypervisor that does not switch between host and guest VMIDs outside
/// of a vCPU run.
pub fn vmPerCoreInit() void {
    // VBAR_EL2 is per-core on ARM; every CPU brought online must install
    // the kernel's own EL2 vector table via the bootloader HVC stub before
    // any HVC from this core can reach the kernel's world-switch handlers.
    installHypVectors();
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
    /// `arg` = guest IPA of a stage-2 entry that was just mutated.
    /// Dispatches to `hvc_tlbi_ipa` which issues
    /// `tlbi ipas2e1is, arg>>12; dsb ish; tlbi vmalle1is; dsb ish; isb`
    /// at EL2. Required because `TLBI IPAS2E1IS` is EL2-only
    /// (ARM ARM D7.7); the EL1 kernel therefore cannot issue it
    /// directly. Returns 0.
    tlbi_ipa = 2,
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

// HCR_EL2 bits (ARM ARM D13.2.46, "HCR_EL2, Hypervisor Configuration Register").
// Only the bits this file actually touches are named; the rest stay 0 unless
// a future change explicitly opts them in.
pub const HCR_EL2_VM: u64 = 1 << 0; // stage-2 translation enable
pub const HCR_EL2_SWIO: u64 = 1 << 1; // set/way IO is set-to-one (RES1 on modern impls)
pub const HCR_EL2_FMO: u64 = 1 << 3; // route physical FIQ to EL2 / enable vFIQ
pub const HCR_EL2_IMO: u64 = 1 << 4; // route physical IRQ to EL2 / enable vIRQ
pub const HCR_EL2_AMO: u64 = 1 << 5; // route physical SError to EL2 / enable vSError
pub const HCR_EL2_VF: u64 = 1 << 6; // virtual FIQ pending (set by vgic inject)
pub const HCR_EL2_VI: u64 = 1 << 7; // virtual IRQ pending (set by vgic inject)
pub const HCR_EL2_TWI: u64 = 1 << 13; // trap WFI from EL1/EL0 to EL2
pub const HCR_EL2_TWE: u64 = 1 << 14; // trap WFE from EL1/EL0 to EL2
pub const HCR_EL2_TID0: u64 = 1 << 15; // trap ID group 0 reads (AArch32 feature ids)
pub const HCR_EL2_TID1: u64 = 1 << 16; // trap ID group 1 reads
pub const HCR_EL2_TID2: u64 = 1 << 17; // trap ID group 2 reads (CTR/DCZID/CCSIDR...)
pub const HCR_EL2_TID3: u64 = 1 << 18; // trap ID group 3 reads (ID_AA64*_EL1)
pub const HCR_EL2_TSC: u64 = 1 << 19; // trap SMC from EL1 to EL2
pub const HCR_EL2_TIDCP: u64 = 1 << 20; // trap impl-defined sysregs at EL1
pub const HCR_EL2_TACR: u64 = 1 << 21; // trap ACTLR_EL1 access
pub const HCR_EL2_TTLB: u64 = 1 << 25; // trap TLB maintenance (NOT set — too slow)
pub const HCR_EL2_TVM: u64 = 1 << 26; // trap VM sysregs writes (NOT set — too slow)
pub const HCR_EL2_TGE: u64 = 1 << 27; // "host EL2" — MUST stay 0 for an EL1 guest
pub const HCR_EL2_TRVM: u64 = 1 << 30; // trap VM sysregs reads (NOT set — too slow)
pub const HCR_EL2_RW: u64 = 1 << 31; // EL1 execution state = AArch64 (not AArch32)

/// Default HCR_EL2 mask for a freshly constructed AArch64 Linux guest.
///
/// Rationale per bit (ARM ARM D13.2.46):
///   VM    : stage-2 translation on — without this, guest PAs pass straight
///           through to host PA and the whole IPA abstraction collapses.
///   SWIO  : set/way IO treated as inner-shareable. Linux issues set/way
///           maintenance during early boot; letting those escape to the
///           host would evict host lines. RES1 on ARMv8.0+.
///   FMO/IMO/AMO : physical FIQ/IRQ/SError route to EL2 and the matching
///           virtual {F,I,SE} delivery is enabled. Required for any vGIC
///           or vSError injection to be visible to the guest.
///   TWI   : trap WFI so guest halts exit cleanly into the run loop.
///   TWE   : trap WFE — optional, but keeps spinlock-loop stalls observable
///           to the VMM instead of burning guest TIME.
///   TID0/1/2/3 : trap ID register reads. Needed so the VmPolicy ID register
///           response table (see `VmPolicy.id_reg_responses`) can virtualize
///           ID_AA64*_EL1 per-VM rather than leaking the raw host features.
///   TSC   : trap SMC so guest SMC calls exit to the hyp and are decoded by
///           the SMCCC shim, not silently forwarded to EL3.
///   TIDCP : trap implementation-defined sysregs at EL1. Belt-and-braces
///           against CPU-errata knobs the guest has no business poking.
///   TACR  : trap ACTLR_EL1 (implementation-defined auxiliary control).
///   RW    : lower EL (EL1/EL0) runs in AArch64. We do not support AArch32
///           guests in this port.
///
/// Bits deliberately left zero:
///   TGE   : if TGE=1, EL1 exceptions get forwarded to EL2 as "host EL2"
///           routing, which breaks every EL1 guest. Linux guests MUST see
///           TGE=0.
///   TVM/TRVM : trapping the VM sysreg family (SCTLR/TTBR*/TCR/MAIR/...) on
///           every guest access is a performance catastrophe — Linux
///           programs SCTLR_EL1 dozens of times during early boot. We let
///           the guest manage its own stage-1 state and rely on stage-2
///           containment.
///   TTLB  : trapping TLB maintenance is likewise too expensive; stage-2
///           VMID tagging already isolates guest TLB entries from the
///           host (ARM ARM D5.10.1).
///   VI/VF : cleared at entry time. `vgic.prepareEntry` OR's them in when
///           a virtual interrupt is pending; clearing them here gives the
///           vgic a known starting point each run.
///   TLOR  : not set — LORegions are not emulated.
///   HA/HD : not set in VTCR_EL2 either; hw access/dirty flag updates are
///           a later-wave optimisation.
pub const HCR_EL2_LINUX_GUEST: u64 = HCR_EL2_VM |
    HCR_EL2_SWIO |
    HCR_EL2_FMO |
    HCR_EL2_IMO |
    HCR_EL2_AMO |
    HCR_EL2_TWI |
    HCR_EL2_TWE |
    HCR_EL2_TID0 |
    HCR_EL2_TID1 |
    HCR_EL2_TID2 |
    HCR_EL2_TID3 |
    HCR_EL2_TSC |
    HCR_EL2_TIDCP |
    HCR_EL2_TACR |
    HCR_EL2_RW;

/// VTCR_EL2 value for our stage-2 config (ARM ARM D13.2.150).
///
/// Field map:
///   T0SZ[5:0]   : input address size = 64 - T0SZ. We use STAGE2_T0SZ=34
///                 → 30-bit (1 GiB) IPA. The stage-2 walker in this file
///                 is hardcoded to a 2-level walk (level 2 root → level 3
///                 leaf) that matches exactly this (T0SZ,SL0) pair; see
///                 the block comment above `stage2L2Idx`. A future wave
///                 will widen this to a 4-level walker and derive T0SZ
///                 from ID_AA64MMFR0_EL1.PARange at init time.
///   SL0[7:6]    : starting level. With 4K granule + T0SZ in [25..33] a
///                 value of 0 starts the walk at level 2 (1 GiB region,
///                 level-2 root, level-3 leaves). ARM ARM D8-2540 Table.
///   IRGN0[9:8]  : inner cacheability of stage-2 table walks = 0b01
///                 (Normal memory, Inner Write-Back Write-Allocate
///                 Cacheable).
///   ORGN0[11:10]: outer cacheability, same encoding.
///   SH0[13:12]  : shareability = 0b11 (Inner Shareable). Mandatory for
///                 SMP-coherent stage-2 walks.
///   TG0[15:14]  : granule size = 0b00 (4 KiB) — matches the descriptor
///                 layout used by `mapGuestPage`.
///   PS[18:16]   : physical address size for the stage-2 output.
///                 0b010 = 40 bits, the baseline assumed by the port.
///   HA/HD       : left 0. Hardware access/dirty flag update is a later
///                 optimisation that also needs stage-2 descriptor format
///                 changes to land first.
pub fn vtcrEl2Value() u64 {
    const t0sz: u64 = STAGE2_T0SZ; // 34 → 1 GiB IPA (matches 2-level walker)
    const sl0: u64 = 0; // start at level 2 (w/ 4K, T0SZ=34)
    const irgn0: u64 = 0b01; // Normal WB WA cacheable
    const orgn0: u64 = 0b01;
    const sh0: u64 = 0b11; // Inner shareable
    const tg0: u64 = 0b00; // 4 KiB granule
    const ps: u64 = 0b010; // 40-bit PA
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
            // ARM ARM D13.2.39 ESR_EL2 ISS for Data Abort / Instruction
            // Abort from a lower Exception level. HPFAR_EL2 bits [39:4]
            // hold IPA bits [47:12]; FAR_EL2 supplies the low 12 bits.
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
                .sign_extend = (iss & (1 << 21)) != 0,
                .reg64 = (iss & (1 << 15)) != 0,
                .acqrel = (iss & (1 << 14)) != 0,
                .fsc = @intCast(iss & 0x3F),
            } };
        },
        0x00 => .{ .unknown_ec = 0 },
        else => .{ .unknown = esr },
    };
}

/// Host FPSIMD save slot used by the eager save/restore path in `vmResume`.
///
/// Layout matches `FxsaveArea` so the same save/load asm sequences work for
/// both host and guest state:
///
///   [0x000 .. 0x200)  V0..V31  — 32 × 128-bit SIMD regs, byte offset = idx*16
///   [0x200 .. 0x208)  FPCR     — FP control (D13.2.48)
///   [0x208 .. 0x210)  FPSR     — FP status  (D13.2.52)
///
/// ARM ARM B1.2.2 defines the V-register file; the kernel's host threads
/// can use FPSIMD (CPACR_EL1.FPEN was set at boot — see init.zig and
/// smp.zig) so the live host FP register file on entry to `vmResume` is
/// meaningful and must be preserved across the guest run.
pub const HostFpState = extern struct {
    v: [32][16]u8 align(16) = @splat(@splat(0)),
    fpcr: u64 = 0,
    fpsr: u64 = 0,
};

/// Per-vCPU scratch the EL2 hyp stub reads/writes through PAs. Owned by
/// the VCpu object (see `kernel/arch/aarch64/kvm/vcpu.zig`) so concurrent
/// vCPUs don't share storage. All fields must live in physmap-backed
/// memory so `PAddr.fromVAddr(..., null)` is a valid VA→PA translation.
///
/// `host_fp` is a scratch slot used by the eager FPSIMD save/restore
/// wrapper around `hypCall(.vcpu_run, ...)` — it only needs to live as long
/// as a single vmResume call, but storing it per-vCPU keeps `vmResume`
/// reentrancy-safe without per-cpu TLS plumbing.
pub const ArchScratch = extern struct {
    ctx: WorldSwitchCtx = .{},
    host_save: HostSave = .{},
    host_fp: HostFpState align(16) = .{},
};

pub fn vmResume(
    guest_state: *GuestState,
    vm_structures: PAddr,
    guest_fxsave: *align(16) FxsaveArea,
    arch_scratch: *align(16) ArchScratch,
    vmid_value: u8,
    hcr_override_set: u64,
    hcr_override_clear: u64,
) VmExitInfo {
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
    // VTTBR_EL2 layout (ARM ARM D13.2.151):
    //   [63:48] VMID  — stage-2 TLB tag, managed by kvm/vmid.zig
    //   [47:1]  BADDR — stage-2 root PA (bits [47:x], with `x` dictated
    //                   by VTCR_EL2.T0SZ+SL0). For T0SZ=34 SL0=0 the
    //                   root is a single 4 KiB table, so bits [11:1] of
    //                   BADDR are RES0 and our page-aligned PA fits
    //                   directly.
    //   [0]     CnP   — 0; we don't claim common-not-private.
    ctx.vttbr_el2 = (@as(u64, vmid_value) << 48) | vm_structures.addr;
    ctx.vtcr_el2 = vtcrEl2Value();
    // HCR_EL2 is the union of the per-VM override-set bits with the Linux
    // baseline, minus any override-clear bits. `sysregPassthrough` feeds
    // this: by default we deny (trap) everything the baseline traps, and
    // only dropping a bit into `hcr_override_clear` opens that trap up for
    // the VM. `hcr_override_set` is reserved for future traps that are not
    // in the baseline.
    ctx.hcr_el2 = (HCR_EL2_LINUX_GUEST | hcr_override_set) & ~hcr_override_clear;

    // ---- Eager FPSIMD save/restore around the world switch ----
    //
    // Must stay fused to the hvc so no host Zig code runs between
    // "save host FP" and the guest entry, and similarly nothing between
    // guest exit and "restore host FP". If anything touches V-regs in
    // between we would either clobber host FP state or leak guest FP
    // state into the host.
    //
    // Layout assumptions (asserted at comptime above for ArchScratch and
    // at the FxsaveArea type def):
    //   HostFpState :  V0..V31 @ 0x000, FPCR @ 0x200, FPSR @ 0x208
    //   FxsaveArea  :  V0..V31 @ 0x000, FPCR @ 0x200, FPSR @ 0x208
    //
    // ARM ARM B1.2.2 (V-reg file), D13.2.48 (FPCR), D13.2.52 (FPSR).
    const host_fp_ptr: [*]u8 = @ptrCast(&arch_scratch.host_fp);
    const guest_fp_ptr: [*]u8 = @ptrCast(guest_fxsave);
    asm volatile (
        \\  // Save host V0..V31 to [host_fp + 0x000..0x200]
        \\  stp     q0, q1,   [%[hfp], #0x000]
        \\  stp     q2, q3,   [%[hfp], #0x020]
        \\  stp     q4, q5,   [%[hfp], #0x040]
        \\  stp     q6, q7,   [%[hfp], #0x060]
        \\  stp     q8, q9,   [%[hfp], #0x080]
        \\  stp     q10, q11, [%[hfp], #0x0A0]
        \\  stp     q12, q13, [%[hfp], #0x0C0]
        \\  stp     q14, q15, [%[hfp], #0x0E0]
        \\  stp     q16, q17, [%[hfp], #0x100]
        \\  stp     q18, q19, [%[hfp], #0x120]
        \\  stp     q20, q21, [%[hfp], #0x140]
        \\  stp     q22, q23, [%[hfp], #0x160]
        \\  stp     q24, q25, [%[hfp], #0x180]
        \\  stp     q26, q27, [%[hfp], #0x1A0]
        \\  stp     q28, q29, [%[hfp], #0x1C0]
        \\  stp     q30, q31, [%[hfp], #0x1E0]
        \\  mrs     x2, fpcr
        \\  str     x2, [%[hfp], #0x200]
        \\  mrs     x2, fpsr
        \\  str     x2, [%[hfp], #0x208]
        \\
        \\  // Load guest V0..V31 from [gfp + 0x000..0x200]
        \\  ldr     x2, [%[gfp], #0x200]
        \\  msr     fpcr, x2
        \\  ldr     x2, [%[gfp], #0x208]
        \\  msr     fpsr, x2
        \\  ldp     q0, q1,   [%[gfp], #0x000]
        \\  ldp     q2, q3,   [%[gfp], #0x020]
        \\  ldp     q4, q5,   [%[gfp], #0x040]
        \\  ldp     q6, q7,   [%[gfp], #0x060]
        \\  ldp     q8, q9,   [%[gfp], #0x080]
        \\  ldp     q10, q11, [%[gfp], #0x0A0]
        \\  ldp     q12, q13, [%[gfp], #0x0C0]
        \\  ldp     q14, q15, [%[gfp], #0x0E0]
        \\  ldp     q16, q17, [%[gfp], #0x100]
        \\  ldp     q18, q19, [%[gfp], #0x120]
        \\  ldp     q20, q21, [%[gfp], #0x140]
        \\  ldp     q22, q23, [%[gfp], #0x160]
        \\  ldp     q24, q25, [%[gfp], #0x180]
        \\  ldp     q26, q27, [%[gfp], #0x1A0]
        \\  ldp     q28, q29, [%[gfp], #0x1C0]
        \\  ldp     q30, q31, [%[gfp], #0x1E0]
        \\
        \\  // World switch: x0 = vcpu_run id (1), x1 = ctx PA.
        \\  // The hyp stub preserves %[hfp] / %[gfp] (both map to
        \\  // callee-saved x19..x28 via the Zig asm constraint) across
        \\  // the round trip because the EL2 exit path reloads host
        \\  // x19..x30 from host_save before returning.
        \\  mov     x0, #1
        \\  mov     x1, %[ctxpa]
        \\  hvc     #0
        \\
        \\  // Save guest V0..V31 back into [gfp]
        \\  stp     q0, q1,   [%[gfp], #0x000]
        \\  stp     q2, q3,   [%[gfp], #0x020]
        \\  stp     q4, q5,   [%[gfp], #0x040]
        \\  stp     q6, q7,   [%[gfp], #0x060]
        \\  stp     q8, q9,   [%[gfp], #0x080]
        \\  stp     q10, q11, [%[gfp], #0x0A0]
        \\  stp     q12, q13, [%[gfp], #0x0C0]
        \\  stp     q14, q15, [%[gfp], #0x0E0]
        \\  stp     q16, q17, [%[gfp], #0x100]
        \\  stp     q18, q19, [%[gfp], #0x120]
        \\  stp     q20, q21, [%[gfp], #0x140]
        \\  stp     q22, q23, [%[gfp], #0x160]
        \\  stp     q24, q25, [%[gfp], #0x180]
        \\  stp     q26, q27, [%[gfp], #0x1A0]
        \\  stp     q28, q29, [%[gfp], #0x1C0]
        \\  stp     q30, q31, [%[gfp], #0x1E0]
        \\  mrs     x2, fpcr
        \\  str     x2, [%[gfp], #0x200]
        \\  mrs     x2, fpsr
        \\  str     x2, [%[gfp], #0x208]
        \\
        \\  // Restore host V0..V31 + FPCR/FPSR from [hfp]
        \\  ldr     x2, [%[hfp], #0x200]
        \\  msr     fpcr, x2
        \\  ldr     x2, [%[hfp], #0x208]
        \\  msr     fpsr, x2
        \\  ldp     q0, q1,   [%[hfp], #0x000]
        \\  ldp     q2, q3,   [%[hfp], #0x020]
        \\  ldp     q4, q5,   [%[hfp], #0x040]
        \\  ldp     q6, q7,   [%[hfp], #0x060]
        \\  ldp     q8, q9,   [%[hfp], #0x080]
        \\  ldp     q10, q11, [%[hfp], #0x0A0]
        \\  ldp     q12, q13, [%[hfp], #0x0C0]
        \\  ldp     q14, q15, [%[hfp], #0x0E0]
        \\  ldp     q16, q17, [%[hfp], #0x100]
        \\  ldp     q18, q19, [%[hfp], #0x120]
        \\  ldp     q20, q21, [%[hfp], #0x140]
        \\  ldp     q22, q23, [%[hfp], #0x160]
        \\  ldp     q24, q25, [%[hfp], #0x180]
        \\  ldp     q26, q27, [%[hfp], #0x1A0]
        \\  ldp     q28, q29, [%[hfp], #0x1C0]
        \\  ldp     q30, q31, [%[hfp], #0x1E0]
        :
        : [hfp] "r" (host_fp_ptr),
          [gfp] "r" (guest_fp_ptr),
          [ctxpa] "r" (ctx_pa.addr),
        : .{
            .memory = true,
            .x0 = true,
            .x1 = true,
            .x2 = true,
            .v0 = true,  .v1 = true,  .v2 = true,  .v3 = true,
            .v4 = true,  .v5 = true,  .v6 = true,  .v7 = true,
            .v8 = true,  .v9 = true,  .v10 = true, .v11 = true,
            .v12 = true, .v13 = true, .v14 = true, .v15 = true,
            .v16 = true, .v17 = true, .v18 = true, .v19 = true,
            .v20 = true, .v21 = true, .v22 = true, .v23 = true,
            .v24 = true, .v25 = true, .v26 = true, .v27 = true,
            .v28 = true, .v29 = true, .v30 = true, .v31 = true,
        });

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
// `bootloader/aarch64_el2_drop.zig`). Its sync-lower A64 slot decodes the
// HVC imm16 and, on `HVC_IMM_INSTALL_VBAR_EL2`, writes X0 into VBAR_EL2.
// `installHypVectors()` uses that hand-off to swap the stub for the
// `__hyp_vectors` table defined below, at which point HVCs land in
// `hyp_sync_lower_a64` and the full world-switch dispatcher is live.
//
// Symbols defined here (referenced from `__hyp_vectors`):
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

/// Kernel EL2 vector table. 16 slots × 0x80 bytes each, 2 KiB aligned.
///
/// ARM ARM D1.10.2 vector layout (offset → vector):
///   0x000 sync  EL2t     0x080 irq  EL2t     0x100 fiq  EL2t     0x180 serror EL2t
///   0x200 sync  EL2h     0x280 irq  EL2h     0x300 fiq  EL2h     0x380 serror EL2h
///   0x400 sync  lowerA64 0x480 irq  lowerA64 0x500 fiq  lowerA64 0x580 serror lowerA64
///   0x600 sync  lowerA32 0x680 irq  lowerA32 0x700 fiq  lowerA32 0x780 serror lowerA32
///
/// Only the "sync lower A64" slot is wired up: it branches into
/// `hyp_sync_lower_a64`, which decodes HVC-vs-guest-exit via tpidr_el2.
/// Every other slot is a tight `b .` loop — the kernel never raises
/// async exceptions to EL2 and the direct-kernel path does not support
/// AArch32 guests, so any entry there is a bug we want to observe as a
/// hang rather than a silent wild branch.
export fn __hyp_vectors() align(2048) callconv(.naked) noreturn {
    asm volatile (
    // +0x000 sync EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x080 irq EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x100 fiq EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x180 serror EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x200 sync EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x280 irq EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x300 fiq EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x380 serror EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x400 sync lower A64 — host hvc or guest exit
        \\        b       hyp_sync_lower_a64
        \\        .balign 0x80
        // +0x480 irq lower A64
        \\        b       .
        \\        .balign 0x80
        // +0x500 fiq lower A64
        \\        b       .
        \\        .balign 0x80
        // +0x580 serror lower A64
        \\        b       .
        \\        .balign 0x80
        // +0x600..+0x780 lower AArch32 (unused)
        \\        b       .
        \\        .balign 0x80
        \\        b       .
        \\        .balign 0x80
        \\        b       .
        \\        .balign 0x80
        \\        b       .
    );
}

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
        \\  cmp     x0, #2
        \\  b.eq    hvc_tlbi_ipa
        \\  // Unknown id — return -1.
        \\  mov     x0, #-1
        \\  eret
    );
}

// hvc_tlbi_ipa — M4 stage-2 IPA invalidation from the EL1 kernel.
//
// On entry:
//   x0 = HypCallId.tlbi_ipa (2) — discarded.
//   x1 = guest IPA (byte address) of the stage-2 leaf that was mutated.
//
// `TLBI IPAS2E1IS` takes a 36-bit IPA page number in bits [35:0] of its
// register operand (ARM ARM K.a D7.7.7 "TLBI IPAS2E1IS, Xt"). We shift
// the byte IPA right by 12 to get that page number. The sequence is:
//
//   dsb ishst        — order prior stage-2 table stores before the TLBI
//   tlbi ipas2e1is   — invalidate the specific IPA across the IS domain
//                      (all EL0/EL1 entries that used stage-2 for this
//                      IPA under the current VMID)
//   dsb ish          — wait for the TLBI broadcast to complete everywhere
//   tlbi vmalle1is   — nuke stage-1 walk caches that may have consumed
//                      the stale stage-2 descriptor on any IS core
//                      (cheap; strictly required only for combined
//                      stage-1+stage-2 walks, ARM ARM D5.10.2)
//   dsb ish          — wait for the stage-1 TLBI to settle
//   isb              — context synchronization so the kernel sees the
//                      post-invalidate state on return
//
// The VMID programmed in VTTBR_EL2 selects which VM the IPA belongs to;
// the caller (EL1 kernel) must have already written VTTBR_EL2 for the
// target VM via the world-switch entry path — or be invalidating a VM
// whose VMID is otherwise already loaded, which is the common case
// because `mapGuestPage`/`unmapGuestPage` are driven from VMM syscalls
// on the owning process's core while VTTBR_EL2 holds that VM's VMID.
export fn hvc_tlbi_ipa() callconv(.naked) noreturn {
    asm volatile (
        \\  lsr     x1, x1, #12
        \\  dsb     ishst
        \\  tlbi    ipas2e1is, x1
        \\  dsb     ish
        \\  tlbi    vmalle1is
        \\  dsb     ish
        \\  isb
        \\  mov     x0, #0
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

/// Stage-2 leaf memory type. Selects `MemAttr[3:0]` on the Stage2Entry
/// per ARM ARM K.a D5.5.5 Table D5-37 "Stage 2 MemAttr[3:0]":
///
///   0b1111 — Normal, Inner+Outer Write-Back, Write-Allocate, non-transient
///   0b0000 — Device-nGnRnE (strongly-ordered MMIO, no gathering, no
///            reordering, no early ack)
///
/// Used by `mapGuestPage` to let the caller request a device mapping
/// for stage-2 MMIO windows the VMM intends to emulate — guest writes
/// to a Device-nGnRnE page are guaranteed to fault to the hypervisor
/// in program order, which is the ARM equivalent of x86 EPT's "UC"
/// type for an MMIO page.
pub const Stage2MemAttr = enum(u4) {
    normal_wb = 0b1111,
    device_nGnRnE = 0b0000,
};

/// Well-known guest-physical MMIO windows for the "virt" machine layout
/// Zag's VMM currently exposes to guests. Used by `stage2MemAttrForIpa`
/// to pick Device-nGnRnE for pages the VMM is going to emulate. This is
/// intentionally a closed enumeration — any VMM-specific device memory
/// the user wires up through `vm_guest_map` still lands as Normal WB
/// unless the map reply grows an explicit `memattr` flag (TODO #125).
///
/// References:
///   - ARM DDI 0183G     PL011 UART (base 0x09000000 on virt)
///   - virtio-mmio spec  §4.2.2 (0x0a000000..0x0a000e00 on virt)
///   - GICv3 §12         GICD / GICR bases live in `kvm.vgic` and are
///                       already matched by `Vm.tryHandleMmio` before
///                       the stage-2 mapping path is ever reached.
pub const PL011_MMIO_BASE: u64 = 0x09000000;
pub const PL011_MMIO_SIZE: u64 = 0x1000;
pub const VIRTIO_MMIO_BASE: u64 = 0x0a000000;
pub const VIRTIO_MMIO_SIZE: u64 = 0x0e00;

/// Pick the stage-2 memory type for `guest_phys` by IPA window match.
/// Anything outside a known device window is treated as Normal WB.
///
/// TODO(#125): extend `VmReplyAction.map_memory` with an explicit
/// `memattr` field so the VMM can mark arbitrary pages as device
/// without needing kernel awareness of their IPA. Until then, this
/// closed table covers the set of devices every v1 guest actually
/// touches (vGIC is handled inline before we get here).
pub fn stage2MemAttrForIpa(guest_phys: u64) Stage2MemAttr {
    if (guest_phys >= PL011_MMIO_BASE and guest_phys < PL011_MMIO_BASE + PL011_MMIO_SIZE) {
        return .device_nGnRnE;
    }
    if (guest_phys >= VIRTIO_MMIO_BASE and guest_phys < VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE) {
        return .device_nGnRnE;
    }
    return .normal_wb;
}

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
/// supplied rights (bit 0 = read, bit 1 = write, bit 2 = exec) and
/// memory type (`memattr`). `memattr = .normal_wb` is the default for
/// guest RAM; `memattr = .device_nGnRnE` is used for MMIO windows the
/// VMM either emulates directly or passes through to real device
/// memory. See ARM ARM K.a D5.5.5 Table D5-37 for the full list of
/// legal stage-2 MemAttr encodings.
///
/// Walks the level-2 root, allocates a level-3 page if the L2 slot is
/// empty, then writes the leaf descriptor. Issues a per-IPA
/// `TLBI IPAS2E1IS, ipa>>12; DSB ISH` afterwards via
/// `stage2InvalidateIpa` so stale speculative stage-2 walks cannot hit
/// the new descriptor with an old value.
pub fn mapGuestPage(
    vm_structures: PAddr,
    guest_phys: u64,
    host_phys: PAddr,
    rights: u8,
    memattr: Stage2MemAttr,
) !void {
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

    // MemAttr per caller selection. ARM ARM D5.5.5 Table D5-37:
    //   0b1111 = Normal Inner WB, Outer WB, non-transient (guest RAM)
    //   0b0000 = Device-nGnRnE (MMIO, strongly-ordered, no gathering)
    const mem_attr: u4 = @intFromEnum(memattr);

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

/// Invalidate any cached stage-2 translation for `guest_phys` (byte
/// address, page-aligned) in the current VM's VMID.
///
/// `TLBI IPAS2E1IS, <ipa>>>12` is the architectural instruction for
/// stage-2 invalidation (ARM ARM K.a D7.7 "TLB maintenance
/// instructions"), but it is EL2-only: executing it from EL1 is
/// UNDEFINED and would trap. The Zag kernel runs at EL1, so we route
/// through the `hvc_tlbi_ipa` hyp stub (HypCallId.tlbi_ipa) which
/// executes the full
///     dsb ishst ; tlbi ipas2e1is ; dsb ish ; tlbi vmalle1is ; dsb ish ; isb
/// sequence at EL2 against the currently-loaded VTTBR_EL2. Called
/// from every stage-2 mutation site (`mapGuestPage`, `unmapGuestPage`,
/// and any future attribute-change path) so speculative walks can
/// never observe a stale descriptor once this function returns.
///
/// Range invalidations (block descriptors, VMID rollover) should keep
/// using `vmalls12e1is` — see the world-switch entry path in
/// `hvc_vcpu_run`, which already issues that for VMID rollover.
///
/// Callers must pass a page-aligned byte IPA; `hvc_tlbi_ipa` shifts
/// right by 12 internally before issuing the TLBI, per the register
/// format in ARM ARM D7.7.7.
pub fn invalidateStage2Ipa(guest_phys: u64) void {
    std.debug.assert(std.mem.isAligned(guest_phys, paging.PAGE4K));
    _ = hypCall(.tlbi_ipa, guest_phys);
}

fn stage2InvalidateIpa(guest_phys: u64) void {
    invalidateStage2Ipa(guest_phys);
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

/// Decoded (op0,op1,crn,crm,op2) sysreg key used by
/// `sysregPassthroughOverride`. The packed `sysreg_id` layout comes from
/// the `vm_sysreg_passthrough` syscall and matches
/// `kvm.vm.isSecurityCriticalSysreg`:
///
///   bits [15:14] Op0
///   bits [13:11] Op1
///   bits [10:7]  CRn
///   bits [6:3]   CRm
///   bits [2:0]   Op2
pub const SysregKey = packed struct {
    op0: u8,
    op1: u8,
    crn: u8,
    crm: u8,
    op2: u8,

    pub fn decode(encoded: u32) SysregKey {
        return .{
            .op0 = @intCast((encoded >> 14) & 0x3),
            .op1 = @intCast((encoded >> 11) & 0x7),
            .crn = @intCast((encoded >> 7) & 0xF),
            .crm = @intCast((encoded >> 3) & 0xF),
            .op2 = @intCast(encoded & 0x7),
        };
    }
};

/// HCR_EL2 trap group a particular sysreg belongs to. Only the groups that
/// `HCR_EL2_LINUX_GUEST` forces on are meaningful here — allowing
/// passthrough of a sysreg outside one of these groups is a no-op because
/// the baseline already lets it through. See `HCR_EL2_LINUX_GUEST` above
/// for the full rationale table.
const HcrTrapGroup = enum {
    /// No HCR bit governs this sysreg — passthrough request is vacuous.
    none,
    /// ACTLR_EL1 (impl-defined auxiliary control) — HCR_EL2.TACR.
    /// ARM ARM D13.2.46 TACR; sysreg encoding op0=3 op1=0 crn=1 crm=0 op2=1.
    tacr,
    /// Impl-defined EL1 sysregs — HCR_EL2.TIDCP.
    /// ARM ARM D13.2.46 TIDCP covers CRn ∈ {9, 10, 11, 15} with the
    /// implementation-defined flag. We match CRn in {11, 15} (the two most
    /// commonly used by platform-specific errata knobs on the CPUs this
    /// port targets — Cortex-A76 uses CRn=11 for CPUACTLR, CRn=15 for
    /// CPUECTLR/L2CTLR).
    tidcp,
    /// Stage-1 "VM" sysreg family — HCR_EL2.TVM (writes) / HCR_EL2.TRVM
    /// (reads). ARM ARM D13.2.46 TVM enumerates:
    ///   SCTLR_EL1, TTBR0_EL1, TTBR1_EL1, TCR_EL1, ESR_EL1, FAR_EL1,
    ///   AFSR0_EL1, AFSR1_EL1, MAIR_EL1, AMAIR_EL1, CONTEXTIDR_EL1.
    tvm,
};

/// Classify a sysreg key into the HCR_EL2 trap group that governs its
/// EL1 access, or `.none` if no bit in `HCR_EL2_LINUX_GUEST` covers it.
///
/// Sysreg encodings cross-referenced against ARM ARM C5.3 "System register
/// encoding". All entries are op0=3, op1=0 (the EL1-accessible half).
fn classifySysreg(key: SysregKey) HcrTrapGroup {
    if (key.op0 != 3 or key.op1 != 0) return .none;

    // ACTLR_EL1 — op0=3 op1=0 CRn=1 CRm=0 op2=1 (ARM ARM D13.2.9).
    if (key.crn == 1 and key.crm == 0 and key.op2 == 1) return .tacr;

    // TVM-governed stage-1 VM sysregs. Each entry is (CRn, CRm, op2).
    //   SCTLR_EL1       (1, 0, 0)    D13.2.119
    //   TTBR0_EL1       (2, 0, 0)    D13.2.137
    //   TTBR1_EL1       (2, 0, 1)    D13.2.139
    //   TCR_EL1         (2, 0, 2)    D13.2.131
    //   AFSR0_EL1       (5, 1, 0)    D13.2.23
    //   AFSR1_EL1       (5, 1, 1)    D13.2.24
    //   ESR_EL1         (5, 2, 0)    D13.2.39
    //   FAR_EL1         (6, 0, 0)    D13.2.41
    //   MAIR_EL1        (10, 2, 0)   D13.2.93
    //   AMAIR_EL1       (10, 3, 0)   D13.2.25
    //   CONTEXTIDR_EL1  (13, 0, 1)   D13.2.31
    switch (key.crn) {
        1 => if (key.crm == 0 and key.op2 == 0) return .tvm,
        2 => if (key.crm == 0 and key.op2 <= 2) return .tvm,
        5 => {
            if (key.crm == 1 and key.op2 <= 1) return .tvm;
            if (key.crm == 2 and key.op2 == 0) return .tvm;
        },
        6 => if (key.crm == 0 and key.op2 == 0) return .tvm,
        10 => {
            if (key.crm == 2 and key.op2 == 0) return .tvm;
            if (key.crm == 3 and key.op2 == 0) return .tvm;
        },
        13 => if (key.crm == 0 and key.op2 == 1) return .tvm,
        else => {},
    }

    // Impl-defined groups governed by TIDCP.
    if (key.crn == 11 or key.crn == 15) return .tidcp;

    return .none;
}

/// Update a VM's HCR_EL2 override-set/override-clear pair based on a
/// passthrough request. Baseline `HCR_EL2_LINUX_GUEST` has every relevant
/// trap bit *set* (deny-by-default), so "allow passthrough" means dropping
/// the matching bit into `override_clear`; "deny passthrough" removes it
/// from `override_clear` (returning to the baseline's trap-on state).
///
/// The TVM/TRVM group is split read/write: `allow_write` gates TVM and
/// `allow_read` gates TRVM. For TACR and TIDCP the baseline does not
/// distinguish direction, so either flag being set opens the group.
///
/// Sysregs that do not map to a HCR_EL2 bit managed by the baseline are
/// silently ignored — `isSecurityCriticalSysreg` in the kvm layer already
/// rejected the dangerous encodings before we got here.
pub fn sysregPassthroughOverride(
    sysreg_id: u32,
    allow_read: bool,
    allow_write: bool,
    override_set: *u64,
    override_clear: *u64,
) void {
    _ = override_set; // reserved for future traps not in the baseline
    const key = SysregKey.decode(sysreg_id);
    const group = classifySysreg(key);
    const any = allow_read or allow_write;
    switch (group) {
        .none => {},
        .tacr => {
            if (any) {
                override_clear.* |= HCR_EL2_TACR;
            } else {
                override_clear.* &= ~HCR_EL2_TACR;
            }
        },
        .tidcp => {
            if (any) {
                override_clear.* |= HCR_EL2_TIDCP;
            } else {
                override_clear.* &= ~HCR_EL2_TIDCP;
            }
        },
        .tvm => {
            // TVM is *write*-side, TRVM is *read*-side. Only drop a bit
            // once every sysreg in the group has been opened — but the
            // current API is per-sysreg. For now treat any allow_write in
            // the group as "clear TVM" and any allow_read as "clear
            // TRVM". This is correct for the common case (VMM opens the
            // whole family at once to let the guest own its stage-1
            // state) and coarser than necessary otherwise. TODO: track a
            // per-sysreg allow mask and only clear TVM/TRVM when every
            // member of the group is allowed.
            if (allow_write) {
                override_clear.* |= HCR_EL2_TVM;
            } else {
                override_clear.* &= ~HCR_EL2_TVM;
            }
            if (allow_read) {
                override_clear.* |= HCR_EL2_TRVM;
            } else {
                override_clear.* &= ~HCR_EL2_TRVM;
            }
        },
    }
}
