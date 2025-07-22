//! Early boot-time physical memory region tracker and virtual memory mapper.
//!
//! This module defines the `MemoryRegionMap`, which parses memory regions from the bootloader,
//! filters and tracks usable physical memory, and identity-maps it into the virtual address space.
//!
//! It is used during early kernel initialization to:
//! - Track physical memory regions for later use by the physical memory manager (PMM).
//! - Bootstrap page table mappings for all usable memory above the kernel and page tables.
//! - Provide coarse-grained allocation until the buddy allocator takes over.
//!
//! This allows the PMM to be initialized with full access to all remaining usable memory.

const std = @import("std");

const multiboot = @import("../arch/x86_64/multiboot.zig");

const MemoryRegionType = multiboot.MemoryRegionType;

/// Maximum number of memory regions the `MemoryRegionMap` can track from the bootloader's memory map.
const MAX_REGIONS = 32;

/// Represents a physical memory region reported by the bootloader.
///
/// Each region includes a base physical address, a length in bytes,
/// and a classification via `MemoryRegionType` (e.g., Available, Reserved).
const MemoryRegion = struct {
    /// Starting physical address of the region.
    addr: u64,

    /// Length of the region in bytes.
    len: u64,

    /// Type of region (e.g., usable, reserved, ACPI reclaimable).
    region_type: MemoryRegionType,
};

pub const MemoryRegionMap = struct {
    region_count: usize = 0,
    regions: [MAX_REGIONS]MemoryRegion,

    pub fn init() MemoryRegionMap {
        return MemoryRegionMap{
            .region_count = 0,
            .regions = undefined,
        };
    }

    pub fn appendRegion(
        ctx: *anyopaque,
        addr: u64,
        len: u64,
        region_type: MemoryRegionType,
    ) void {
        const self: *MemoryRegionMap = @alignCast(@ptrCast(ctx));

        self.regions[self.region_count] = MemoryRegion{
            .addr = addr,
            .len = len,
            .region_type = region_type,
        };
        self.region_count += 1;
        std.debug.assert(self.region_count <= MAX_REGIONS);
    }
};
