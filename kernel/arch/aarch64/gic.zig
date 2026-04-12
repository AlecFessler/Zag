//! ARM Generic Interrupt Controller (GIC) driver.
//!
//! The GIC is the ARM equivalent of x86's APIC (Local APIC + IO APIC).
//! It handles interrupt routing, prioritization, and inter-processor interrupts.
//! Supports GICv2 and GICv3 — detect version from MADT/GICD_IIDR.
//!
//! GIC architecture (ARM IHI 0069, GICv3 Architecture Specification):
//!
//!   Distributor (GICD_*): Global, one per system.
//!     - Manages SPI (Shared Peripheral Interrupt) enable/disable/routing.
//!     - Base address discovered from ACPI MADT GIC Distributor structure.
//!     - GICD_CTLR: enable/disable distributor.
//!     - GICD_ISENABLER/GICD_ICENABLER: per-interrupt enable/disable (for maskIrq/unmaskIrq).
//!     - GICD_ITARGETSR (GICv2) / GICD_IROUTER (GICv3): SPI → core routing.
//!
//!   Redistributor (GICR_*, GICv3 only): One per core.
//!     - Manages SGI/PPI enable/priority for its core.
//!     - Discovered from ACPI MADT GIC Redistributor structure.
//!
//!   CPU Interface (GICC_* for GICv2, ICC_*_EL1 system registers for GICv3):
//!     - Per-core, handles interrupt acknowledgement and EOI.
//!     - GICv2: MMIO at base from MADT GIC CPU Interface structure.
//!       GICC_IAR: read to acknowledge interrupt (returns interrupt ID).
//!       GICC_EOIR: write to signal End Of Interrupt.
//!     - GICv3: system registers ICC_IAR1_EL1, ICC_EOIR1_EL1, ICC_SGI1R_EL1.
//!
//! Interrupt ID ranges:
//!   0-15:    SGI (Software Generated Interrupts) — used for IPIs.
//!   16-31:   PPI (Private Peripheral Interrupts) — per-core (e.g., timer).
//!   32-1019: SPI (Shared Peripheral Interrupts) — device IRQs.
//!
//! Dispatch interface mapping:
//!   coreCount()                → count MADT GIC CPU Interface entries
//!   coreID()                   → read MPIDR_EL1 affinity fields
//!   sendIpiToCore(id, vector)  → write ICC_SGI1R_EL1 (GICv3) or GICD_SGIR (GICv2)
//!   maskIrq(irq)              → GICD_ICENABLER[irq/32] |= (1 << irq%32)
//!   unmaskIrq(irq)            → GICD_ISENABLER[irq/32] |= (1 << irq%32)
//!   endOfInterrupt()          → write ICC_EOIR1_EL1 / GICC_EOIR
//!
//! References:
//! - ARM IHI 0048B: GICv2 Architecture Specification
//! - ARM IHI 0069H: GICv3/v4 Architecture Specification
//! - ARM ARM D13.2.83: MPIDR_EL1

const zag = @import("zag");

pub fn coreCount() u64 {
    @panic("aarch64 GIC not implemented");
}

pub fn coreID() u64 {
    // MPIDR_EL1 affinity fields encode the core ID.
    // ARM ARM D13.2.83: Aff0 = core, Aff1 = cluster, etc.
    @panic("aarch64 GIC not implemented");
}

pub fn sendIpiToCore(core_id: u64, vector: u8) void {
    _ = core_id;
    _ = vector;
    @panic("aarch64 GIC not implemented");
}
