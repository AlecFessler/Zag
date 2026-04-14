//! AArch64 bootstrap initialization.
//!
//! Called from dispatch.init() on the BSP (boot processor) before any other
//! arch code runs. Equivalent of x64/init.zig.
//!
//! Initialization sequence:
//! 1. Install exception vector table (MSR VBAR_EL1).
//! 2. Initialize serial output (PL011 UART).
//! 3. Configure and enable the GIC (interrupts remain masked until the
//!    scheduler enables them).
//!
//! References:
//! - ARM ARM D1.10: Exception vectors
//! - ARM ARM D13.2.118: SCTLR_EL1
//! - ARM ARM D13.2.131: TCR_EL1
//! - ARM ARM D13.2.97: MAIR_EL1

const zag = @import("zag");

const exceptions = zag.arch.aarch64.exceptions;
const gic = zag.arch.aarch64.gic;
const paging = zag.arch.aarch64.paging;
const serial = zag.arch.aarch64.serial;

/// BSP early-boot initialization. Called once from dispatch.init() before
/// the scheduler runs.
pub fn init() void {
    const dispatch = zag.arch.dispatch;
    dispatch.earlyDebugChar('1');
    // Resolve MAIR attribute indices against whatever layout the
    // firmware/bootloader left in MAIR_EL1. We cannot safely rewrite
    // MAIR_EL1 under a live MMU (Linux arm64 head.S / proc.S only
    // writes MAIR with the MMU disabled), so we adopt the firmware
    // indices and use them for page-table attr_indx fields.
    paging.initMairIndices();
    dispatch.earlyDebugChar('2');
    exceptions.install();
    dispatch.earlyDebugChar('3');
    serial.init();
    dispatch.earlyDebugChar('4');
    // Force TCR_EL1.T0SZ=16 (48-bit user VA, 4-level walk) NOW, after
    // exitBootServices. UEFI on QEMU virt happens to pick T0SZ=16
    // already, but EDK2/AAVMF on real ARM hardware (Cortex-A76 Pi 5)
    // computes T0SZ from the implementation's PA range and routinely
    // picks T0SZ=25 (39-bit VA, 3-level walk). Our `Process.create`
    // builds a fresh 4-level page table rooted at `addr_space_root`;
    // when the scheduler later writes that root to TTBR0 under a 3-level
    // T0SZ, the hardware walker stops at level 0 with a translation
    // fault on the very first user instruction fetch — the symptom
    // hit on Pi KVM (IFSC=0x04, repeating EC=0x20 from the entry PC).
    //
    // It is safe to change T0SZ here because (a) firmware boot services
    // have already exited, so UEFI no longer needs its identity-mapped
    // TTBR0 walks, and (b) the kernel itself never accesses low VAs
    // until the first user process is scheduled, at which point a fresh
    // 4-level table is written to TTBR0.
    paging.forceT0Sz16();
    // Enable Advanced SIMD / FP access at EL0 and EL1 (CPACR_EL1.FPEN = 0b11).
    // Firmware on QEMU virt happens to leave FPEN enabled already, but PSCI
    // CPU_ON on real hardware (Pi 5) brings secondaries up with CPACR_EL1 at
    // its reset value, which traps any FP/SIMD instruction. LLVM emits q-reg
    // loads for 16-byte struct copies (e.g. reading an `?u64` global via
    // `serial.getBase`), so without FPEN the very first secondary call into
    // any kernel Zig code hits a silent EL1→EL1 sync trap the kernel has no
    // handler for. Setting FPEN here covers the BSP; `secondarySetup` does
    // the same for each AP before it touches Zig code.
    // ARM ARM D13.2.30: CPACR_EL1.FPEN, bits [21:20].
    enableFpAccess();
    // Enable SP alignment checking at EL0 (SCTLR_EL1.SA0, bit 4). Without
    // this, EL0 SP-relative loads with a misaligned SP silently succeed
    // and the §6.8 alignment_fault behaviour cannot be exercised.
    // ARM ARM D13.2.118.
    enableSpAlignmentChecks();
    dispatch.earlyDebugChar('5');
    // NOTE: GIC init is deferred to acpi.parseAcpi() — the distributor
    // and redistributor base addresses come from MADT, which has not
    // been parsed yet at this point.
    dispatch.earlyDebugChar('6');
}

/// Secondary core initialization. Called on each AP after SMP boot brings
/// the core online. Sets up the per-core GIC redistributor and CPU interface.
pub fn perCoreInit(core_idx: usize) void {
    enableFpAccess();
    enableSpAlignmentChecks();
    gic.initSecondaryCoreGic(core_idx);
}

/// Set CPACR_EL1.FPEN (bits [21:20] = 0b11) so Advanced SIMD / FP
/// instructions do not trap at EL0 or EL1. Required on every core — PSCI
/// CPU_ON brings the core up with CPACR_EL1 at its reset value, which may
/// trap SIMD. LLVM emits q-register accesses for 16-byte struct copies
/// inside regular Zig code, so FPEN must be on before any Zig code runs.
/// ARM ARM D13.2.30 — CPACR_EL1.
fn enableFpAccess() void {
    var cpacr: u64 = undefined;
    asm volatile ("mrs %[v], cpacr_el1"
        : [v] "=r" (cpacr),
    );
    cpacr |= (@as(u64, 0b11) << 20);
    asm volatile ("msr cpacr_el1, %[v]"
        :
        : [v] "r" (cpacr),
    );
    asm volatile ("isb");
}

/// Set SCTLR_EL1.SA0 (bit 4) and SCTLR_EL1.SA (bit 3) so a misaligned SP
/// used by a memory access raises an SP-alignment exception at EL0/EL1.
/// ARM ARM D13.2.118 (SCTLR_EL1).
fn enableSpAlignmentChecks() void {
    var sctlr: u64 = undefined;
    asm volatile ("mrs %[v], sctlr_el1"
        : [v] "=r" (sctlr),
    );
    sctlr |= (1 << 3) | (1 << 4);
    asm volatile ("msr sctlr_el1, %[v]"
        :
        : [v] "r" (sctlr),
    );
    asm volatile ("isb");
}
