//! AArch64 SMP (Symmetric Multi-Processing) initialization via PSCI.
//!
//! ARM secondary core bringup uses PSCI CPU_ON, which is fundamentally
//! different from x86's INIT-SIPI-SIPI sequence. There is no assembly
//! trampoline — PSCI takes a target MPIDR and an entry point address,
//! and firmware brings the core to that entry in EL1.
//!
//! Boot sequence:
//! 1. BSP discovers cores from ACPI MADT GIC CPU Interface structures.
//! 2. For each secondary core:
//!    a. Allocate a per-core kernel stack.
//!    b. Call PSCI CPU_ON (function ID 0xC4000003):
//!       - x0 = function ID (0xC4000003 for 64-bit)
//!       - x1 = target MPIDR (affinity fields from MADT)
//!       - x2 = entry point address (kernel function pointer)
//!       - x3 = context ID (passed to entry as x0, can be per-core data ptr)
//!       Invoke via SMC or HVC depending on PSCI conduit.
//!    c. Secondary wakes in EL1 at the entry point with MMU state
//!       determined by firmware (usually MMU off — the entry stub must
//!       enable it and install the kernel page tables).
//! 3. Secondary core initializes: install VBAR_EL1, configure TTBR1_EL1,
//!    enable GIC CPU interface, then enter scheduler.
//!
//! PSCI CPU_ON return values:
//!   0            = SUCCESS
//!   -1           = NOT_SUPPORTED
//!   -2           = INVALID_PARAMETERS
//!   -4           = ALREADY_ON
//!   -5           = ON_PENDING
//!   -9           = INTERNAL_FAILURE
//!
//! References:
//! - ARM DEN 0022D: PSCI 1.1, Section 5.4 (CPU_ON)
//! - ACPI 6.5, Table 5-45: MADT GIC CPU Interface Structure

const zag = @import("zag");

pub fn smpInit() !void {
    @panic("aarch64 SMP init not implemented");
}
