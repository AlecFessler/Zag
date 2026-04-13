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
    paging.setMair();
    dispatch.earlyDebugChar('2');
    exceptions.install();
    dispatch.earlyDebugChar('3');
    serial.init();
    dispatch.earlyDebugChar('4');
    gic.init();
    dispatch.earlyDebugChar('5');
}

/// Secondary core initialization. Called on each AP after SMP boot brings
/// the core online. Sets up the per-core GIC redistributor and CPU interface.
pub fn perCoreInit(core_idx: usize) void {
    gic.initSecondaryCoreGic(core_idx);
}
