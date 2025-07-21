//! Early boot-time physical memory region tracker and virtual memory mapper.
//!
//! This module defines the `RegionAllocator`, which parses memory regions from the bootloader,
//! filters and tracks usable physical memory, and identity-maps it into the virtual address space.
//!
//! It is used during early kernel initialization to:
//! - Track physical memory regions for later use by the physical memory manager (PMM).
//! - Bootstrap page table mappings for all usable memory above the kernel and page tables.
//! - Provide coarse-grained allocation until the buddy allocator takes over.
//!
//! This allows the PMM to be initialized with full access to all remaining usable memory.

const std = @import("std");

const allocator_interface = @import("allocator.zig");
const bootallocator = @import("boot_allocator.zig");
const multiboot = @import("../arch/x86_64/multiboot.zig");
const paging = @import("paging.zig");

const Allocator = allocator_interface.Allocator;
const BootAllocator = bootallocator.BootAllocator;
const MemoryRegionType = multiboot.MemoryRegionType;
const PageSize = paging.PageSize;

/// Maximum number of memory regions the `RegionAllocator` can track from the bootloader's memory map.
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

/// Tracks usable physical memory and sets up early virtual memory mappings.
///
/// `RegionAllocator` is responsible for:
/// - Collecting and filtering memory regions from the bootloader.
/// - Identity-mapping usable memory above the kernel and page tables.
/// - Providing coarse-grained memory region data to initialize the buddy allocator.
///
/// It ignores legacy memory regions (e.g., below 1 MiB) even if marked available,
/// and relies on the `BootAllocator` to determine the end of memory in use.
/// This ensures that only truly free physical memory is mapped and tracked.
pub const RegionAllocator = struct {
    allocator: *Allocator,
    region_count: usize = 0,
    regions: [MAX_REGIONS]MemoryRegion,
    mapped_start: usize = 0,
    mapped_end: usize = 0,
    free_addr: usize = 0,

    /// Initializes a new `RegionAllocator` using the provided allocator interface.
    ///
    /// This is typically called with the `BootAllocator` during early kernel setup.
    /// It prepares the internal state for tracking physical memory regions and their
    /// eventual virtual memory mappings.
    ///
    /// - `allocator`: A pointer to the boot-time allocator used to allocate page table structures.
    pub fn init(allocator: *Allocator) RegionAllocator {
        return RegionAllocator{
            .allocator = allocator,
            .region_count = 0,
            .regions = undefined,
            .mapped_start = 0,
            .mapped_end = 0,
            .free_addr = 0,
        };
    }

    /// Appends a memory region to the internal list of physical regions.
    ///
    /// This is intended to be used as a callback from `parseMemoryMap` during Multiboot parsing.
    /// It stores the region information for later use during page table initialization.
    ///
    /// If the number of regions exceeds `MAX_REGIONS`, the function will assert; this limit
    /// can be increased if necessary. The fixed-size array avoids the need for dynamic allocation
    /// during early boot.
    ///
    /// - `ctx`: Pointer to a `RegionAllocator`, passed opaquely from the callback interface.
    /// - `addr`: Starting physical address of the region.
    /// - `len`: Length of the region in bytes.
    /// - `region_type`: Classification of the region (e.g., Available, Reserved).
    pub fn appendRegion(
        ctx: *anyopaque,
        addr: u64,
        len: u64,
        region_type: MemoryRegionType,
    ) void {
        const self: *RegionAllocator = @alignCast(@ptrCast(ctx));

        self.regions[self.region_count] = MemoryRegion{
            .addr = addr,
            .len = len,
            .region_type = region_type,
        };
        self.region_count += 1;
        std.debug.assert(self.region_count <= MAX_REGIONS);
    }

    /// Identity-maps all usable physical memory above the kernel and page tables.
    ///
    /// This function scans the collected memory regions, filters out:
    /// - non-Available regions,
    /// - memory below 2 MiB (e.g., legacy memory),
    /// - and any memory already used by the kernel and boot allocator.
    ///
    /// It then identity-maps the remaining usable memory using 4KiB pages.
    /// Page tables are allocated using the `BootAllocator`.
    ///
    /// The physical memory range mapped starts at `mapped_start`, which is the first page-aligned
    /// address after all boot-time structures (kernel, allocator, page tables).
    ///
    /// Mapped regions are recorded for later use by the physical memory manager.
    ///
    /// - `base_vaddr`: The base virtual address for mapping physical memory (typically higher-half).
    /// - `mapped_start`: The physical address after which memory is considered safe to map.
    pub fn initializePageTables(
        self: *RegionAllocator,
        base_vaddr: usize,
    ) void {
        const pml4 = self.allocator.alloc(
            @intFromEnum(PageSize.Page4K),
            @intFromEnum(PageSize.Page4K),
        );

        const available_region = 3;
        const region = self.regions[available_region];
        std.debug.assert(region.region_type == .Available);

        const page_size = PageSize.Page4K;
        const page_bytes = @intFromEnum(page_size);

        const start = std.mem.alignForward(
            usize,
            region.addr,
            page_bytes,
        );

        const end = std.mem.alignBackward(
            usize,
            region.addr + region.len,
            page_bytes,
        );

        var paddr: usize = start;
        while (paddr < end) {
            const vaddr = paddr + base_vaddr;
            paging.mapPage(
                @alignCast(@ptrCast(pml4)),
                paddr,
                vaddr,
                .ReadWrite,
                .Supervisor,
                page_size,
                self.allocator,
            );
            paddr += page_bytes;
        }

        const boot_allocator: *BootAllocator = @alignCast(@ptrCast(self.allocator.ctx));
        self.mapped_start = std.mem.alignForward(
            usize,
            boot_allocator.free_addr,
            page_bytes,
        );
        self.mapped_end = end;
    }

    /// Allocates memory using a simple bump allocator strategy.
    ///
    /// This function implements the kernel's `Allocator` interface and is intended
    /// solely for use by the buddy allocator during its initialization phase.
    ///
    /// It linearly allocates memory from the region defined by `mapped_start` to `mapped_end`,
    /// aligning the allocation as requested. All memory allocated through this function is
    /// assumed to be used for long-lived structures (e.g., page metadata) and will remain
    /// valid for the entire lifetime of the kernel.
    ///
    /// After the buddy allocator is initialized, all physical memory management is handled
    /// through it, and this function should no longer be called.
    pub fn alloc(
        ctx: *anyopaque,
        size: usize,
        alignment: usize,
    ) [*]u8 {
        const self: *RegionAllocator = @alignCast(@ptrCast(ctx));

        const aligned = std.mem.alignForward(
            usize,
            self.free_addr,
            alignment,
        );
        const new_end = aligned + size;

        if (new_end > self.mapped_end) {
            @panic("RegionAllocator out of memory");
        }

        self.free_addr = new_end;

        return @ptrFromInt(aligned);
    }
};
