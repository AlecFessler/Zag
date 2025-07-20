//! Early boot-time physical memory region tracker and virtual memory mapper.
//!
//! This module defines the `RegionAllocator`, a temporary allocator used during early
//! kernel boot to track physical memory regions reported by the bootloader and create
//! low-overhead virtual memory mappings. It is designed to work within the limited
//! 2 MiB identity-mapped space established by the bootstrap shim, using large pages
//! (2 MiB) wherever possible to reduce mapping overhead and speed up initialization.
//!
//! The allocator relies on the `BootAllocator` for page table allocations and avoids
//! fine-grained metadata until the physical memory manager (PMM) is initialized.
//! Its purpose is to bootstrap the PMM by identity-mapping all usable physical memory,
//! enabling the PMM to allocate the resources it needs to take over full memory management.

const std = @import("std");

const allocator_interface = @import("allocator.zig");
const multiboot = @import("../arch/x86_64/multiboot.zig");
const paging = @import("paging.zig");

const Allocator = allocator_interface.Allocator;
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

/// Maximum number of mapped regions that can be tracked by the allocator after paging is initialized.
const MAX_MAPPED = 8;

/// Represents a virtual memory mapping created for a physical memory region.
///
/// This includes the virtual address range and the page size used
/// for the mapping. The range is half-open: `[start, end)`.
const MappedRegion = struct {
    /// Starting virtual address of the mapped region (inclusive).
    start: usize,

    /// Ending virtual address of the mapped region (exclusive).
    end: usize,

    /// Page size used to map this region (either 4 KiB or 2 MiB).
    page_size: PageSize,
};

/// A lightweight allocator for boot-time physical memory region tracking and early virtual memory setup.
///
/// `RegionAllocator` is designed for early kernel boot, where it tracks memory regions provided by
/// the bootloader and sets up temporary virtual memory mappings using large (2 MiB) pages when possible.
/// It uses a fixed-capacity internal buffer to avoid heap allocations and minimize memory usage,
/// relying on the `BootAllocator` for any page table allocations needed during mapping.
///
/// This allocator exists to bootstrap the physical memory manager (PMM), which will later take over
/// memory management using finer-grained metadata (e.g., one struct per 4 KiB page). To enable that,
/// `RegionAllocator` ensures all usable physical memory is identity-mapped into the kernel's address space,
/// allowing the PMM to allocate beyond the initial 2 MiB identity-mapped region provided by the bootstrap shim.
///
/// After initialization, this allocator continues to serve as a coarse-grained record of memory layout,
/// while the PMM maintains its own independent virtual memory mappings and higher-resolution page-level tracking.
pub const RegionAllocator = struct {
    allocator: *Allocator,
    region_count: usize = 0,
    regions: [MAX_REGIONS]MemoryRegion,
    mapped_count: usize = 0,
    mapped: [MAX_MAPPED]MappedRegion,

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
            .mapped_count = 0,
            .mapped = undefined,
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
    pub fn append_region(
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

    /// Initializes page tables to map all available physical memory regions into the virtual address space.
    ///
    /// This function scans the collected memory regions, filters out non-available ones,
    /// and maps the usable physical memory using either 2 MiB or 4 KiB pages depending on alignment and size.
    /// Wherever possible, 2 MiB pages are preferred to reduce the number of required page table entries,
    /// minimizing allocations and improving kernel initialization speed.
    ///
    /// Only page-aligned portions of each region are mapped; unaligned edges are excluded.
    /// Mapped regions are tracked in the `mapped` list and are limited by `MAX_MAPPED`.
    /// If this limit is exceeded, the function asserts. It can be raised if needed.
    ///
    /// Page table structures are allocated on demand via the provided allocator, using `paging.mapPage`,
    /// which performs any intermediate table allocations as necessary.
    ///
    /// This routine is intended to support early physical memory management setup by providing
    /// an identity-mapped view of usable memory. It avoids fine-grained tracking to stay within
    /// the small 2 MiB bootstrap-mapped region available during early kernel boot.
    ///
    /// - `base_vaddr`: The virtual base address used to offset each physical address during mapping.
    pub fn initialize_page_tables(
        self: *RegionAllocator,
        base_vaddr: usize,
    ) void {
        const pml4 = self.allocator.alloc(
            @intFromEnum(PageSize.Page4K),
            @intFromEnum(PageSize.Page4K),
        );

        for (0..self.region_count) |region_idx| {
            const region = self.regions[region_idx];
            if (region.region_type != .Available) continue;
            if (region.len < @intFromEnum(PageSize.Page4K)) continue;

            const page_size: PageSize = if (region.len >= @intFromEnum(PageSize.Page2M)) PageSize.Page2M else PageSize.Page4K;
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

            self.mapped[self.mapped_count] = MappedRegion{
                .start = start,
                .end = end,
                .page_size = page_size,
            };
            self.mapped_count += 1;
            std.debug.assert(self.mapped_count <= MAX_MAPPED);

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
        }
    }
};
