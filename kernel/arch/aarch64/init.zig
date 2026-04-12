//! AArch64 bootstrap initialization.
//!
//! Called from dispatch.init() on the BSP (boot processor) before any other
//! arch code runs. Equivalent of x64/init.zig.
//!
//! Initialization sequence:
//! 1. Install exception vector table (MSR VBAR_EL1).
//! 2. Configure MMU-related system registers:
//!    - TCR_EL1: translation control (granule size, address space size, cacheability).
//!      ARM ARM D13.2.131: T0SZ/T1SZ set VA width, TG0/TG1 set granule (4KB).
//!    - MAIR_EL1: memory attribute indirection register (Normal WB, Device-nGnRnE, etc.).
//!      ARM ARM D13.2.97: attribute encoding for page table AttrIndx field.
//!    - SCTLR_EL1: system control register.
//!      ARM ARM D13.2.118: M=MMU enable, C=data cache, I=instruction cache,
//!      WXN=write-execute-never, SPAN=set PAN on exception entry.
//! 3. Enable PAN (Privileged Access Never) if supported:
//!    ARM ARM D5.4.6 — prevents kernel from accessing user pages without
//!    explicit PSTATE.PAN toggle. Check ID_AA64MMFR1_EL1.PAN field.
//! 4. Enable UAO (User Access Override) if supported:
//!    Allows LDTR/STTR in kernel mode to access user pages when PAN is clear.
//! 5. Configure and enable the GIC (interrupts remain masked until the
//!    scheduler enables them).
//! 6. Initialize serial output (PL011 UART).
//!
//! References:
//! - ARM ARM D13.2.118: SCTLR_EL1
//! - ARM ARM D13.2.131: TCR_EL1
//! - ARM ARM D13.2.97: MAIR_EL1
//! - ARM ARM D13.2.66: ID_AA64MMFR1_EL1

const zag = @import("zag");

pub fn init() void {
    @panic("aarch64 init not implemented");
}
