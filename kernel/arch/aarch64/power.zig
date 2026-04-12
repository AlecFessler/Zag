//! AArch64 power management via PSCI (Power State Coordination Interface).
//!
//! PSCI is ARM's standard firmware interface for power management. The kernel
//! calls PSCI functions via SMC (Secure Monitor Call) or HVC (Hypervisor Call)
//! depending on the conduit discovered from the ACPI FADT or device tree.
//!
//! PSCI functions (ARM DEN 0022D, PSCI 1.1):
//!   PSCI_VERSION       (0x84000000): query PSCI version
//!   CPU_ON             (0xC4000003): bring a core online (used by smp.zig)
//!   CPU_OFF            (0x84000002): power down calling core
//!   CPU_SUSPEND        (0xC4000001): enter low-power state
//!   SYSTEM_OFF         (0x84000008): shutdown the system
//!   SYSTEM_RESET       (0x84000009): reboot the system
//!   SYSTEM_RESET2      (0xC4000012): reboot with reason code
//!   SYSTEM_SUSPEND     (0xC400000E): suspend to RAM (if supported)
//!
//! Conduit detection:
//!   ACPI FADT (Section 5.2.9): ARM Boot Architecture Flags bit 1 = PSCI compliant.
//!   PSCI node in ACPI DSDT gives the conduit method (SMC or HVC).
//!
//! Dispatch interface mapping:
//!   powerAction(shutdown)  → PSCI SYSTEM_OFF
//!   powerAction(reboot)    → PSCI SYSTEM_RESET
//!   powerAction(sleep)     → PSCI SYSTEM_SUSPEND (if supported)
//!   cpuPowerAction(idle)   → PSCI CPU_SUSPEND with appropriate power state
//!
//! References:
//! - ARM DEN 0022D: PSCI 1.1 Specification
//! - ACPI 6.5, Section 5.2.9: FADT ARM Boot Architecture Flags
