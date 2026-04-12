//! ARM SMMU (System MMU) driver — aarch64 equivalent of x86 IOMMU (VT-d / AMD-Vi).
//!
//! The SMMU provides DMA remapping: it translates device-initiated memory
//! accesses through a set of page tables, isolating devices from each other
//! and from physical memory they shouldn't access.
//!
//! SMMU versions:
//! - SMMUv2 (ARM IHI 0062): two-stage translation, stream ID based.
//! - SMMUv3 (ARM IHI 0070): command queue / event queue model, IOPMP support.
//!
//! Discovery: SMMU base addresses come from the ACPI IORT (IO Remapping Table),
//! ACPI 6.5 Section 5.2.29. Each IORT SMMU node describes one SMMU instance
//! and its stream ID mappings.
//!
//! Key concepts:
//!   Stream ID:     Identifies the device (like x86 BDF for VT-d).
//!   Stream Table:  Maps stream IDs → Stream Table Entries (STEs).
//!   STE:           Points to a stage-1 and/or stage-2 translation table.
//!   Command Queue: (SMMUv3) software → SMMU commands (invalidate, sync, etc.).
//!   Event Queue:   (SMMUv3) SMMU → software fault/error reports.
//!
//! Dispatch interface mapping:
//!   isAvailable()          → true if IORT contains an SMMU node
//!   mapDmaPages(dev, shm)  → create stage-2 mapping for device's stream ID
//!   unmapDmaPages(...)     → remove stage-2 mapping, invalidate IOTLB
//!   enableTranslation()    → set SMMU_CR0.SMMUEN (SMMUv3) or SMMU_sCR0 (SMMUv2)
//!
//! References:
//! - ARM IHI 0070F: SMMUv3 Architecture Specification
//! - ARM IHI 0062E: SMMUv2 Architecture Specification
//! - ACPI 6.5, Section 5.2.29: IORT

const zag = @import("zag");

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const SharedMemory = zag.memory.shared.SharedMemory;

pub fn isAvailable() bool {
    return false;
}

pub fn mapDmaPages(device: *DeviceRegion, shm: *SharedMemory) !u64 {
    _ = device;
    _ = shm;
    @panic("aarch64 SMMU not implemented");
}

pub fn unmapDmaPages(device: *DeviceRegion, dma_base: u64, num_pages: u64) void {
    _ = device;
    _ = dma_base;
    _ = num_pages;
    @panic("aarch64 SMMU not implemented");
}

pub fn enableTranslation() void {
    @panic("aarch64 SMMU not implemented");
}
