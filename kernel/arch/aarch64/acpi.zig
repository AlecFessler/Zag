//! AArch64 ACPI table parsing.
//!
//! Parses the same ACPI tables as x64 (XSDT, MADT, etc.) but extracts
//! ARM-specific interrupt controller information instead of APIC structures.
//!
//! Key differences from x64:
//! - MADT contains GIC Distributor (type 0x0C), GIC CPU Interface (type 0x0B),
//!   GIC MSI Frame (type 0x0D), and GIC Redistributor (type 0x0E) structures
//!   instead of Local APIC / IO APIC entries.
//! - GTDT (Generic Timer Description Table) provides timer interrupt numbers
//!   and flags for the ARM Generic Timer.
//! - IORT (IO Remapping Table) describes SMMU topology for DMA remapping.
//!
//! References:
//! - ACPI 6.5, Section 5.2.12: Multiple APIC Description Table (MADT)
//! - ACPI 6.5, Table 5-45: GIC CPU Interface (type 0x0B)
//! - ACPI 6.5, Table 5-47: GIC Distributor (type 0x0C)
//! - ACPI 6.5, Section 5.2.25: GTDT
//! - ACPI 6.5, Section 5.2.29: IORT

const zag = @import("zag");

const PAddr = zag.memory.address.PAddr;

pub fn parseAcpi(xsdp_paddr: PAddr) !void {
    _ = xsdp_paddr;
    @panic("aarch64 ACPI parsing not implemented");
}
