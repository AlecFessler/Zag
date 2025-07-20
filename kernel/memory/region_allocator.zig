const std = @import("std");

const allocator_interface = @import("allocator.zig");
const multiboot = @import("../arch/x86_64/multiboot.zig");
const paging = @import("paging.zig");

const Allocator = allocator_interface.Allocator;
const MemoryRegionType = multiboot.MemoryRegionType;
const PageSize = paging.PageSize;

const MAX_REGIONS = 32;
const MemoryRegion = struct {
    addr: u64,
    len: u64,
    region_type: MemoryRegionType,
};

const MAX_MAPPED = 8;
/// Start and end are virtual addresses
const MappedRegion = struct {
    start: usize,
    end: usize, // exclusive
    page_size: paging.PageSize,
};

pub const RegionAllocator = struct {
    allocator: *Allocator,
    region_count: usize = 0,
    regions: [MAX_REGIONS]MemoryRegion,
    mapped_count: usize = 0,
    mapped: [MAX_MAPPED]MappedRegion,

    pub fn init(allocator: *Allocator) RegionAllocator {
        return RegionAllocator{
            .allocator = allocator,
            .region_count = 0,
            .regions = undefined,
            .mapped_count = 0,
            .mapped = undefined,
        };
    }

    /// This interface must match the multiboot.parseMemoryMap callback function interface.
    /// It must be ensured that the caller is not making allocations using the boot allocator
    /// in between calls to this function, or else the allocations this makes will not be contiguous.
    /// This allocation restriction starts as soon as this is struct is initialized as it grabs the
    /// base the allocator will pass on the next allocation by requesting a 0 size allocation.
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

    pub fn initialize_page_tables(
        self: *RegionAllocator,
        base_vaddr: usize,
    ) void {
        const pml4 = self.allocator.alloc(
            PageSize.Page4K.size(),
            PageSize.Page4K.size(),
        );

        for (0..self.region_count) |region_idx| {
            const region = self.regions[region_idx];
            if (region.region_type != .Available) continue;
            if (region.len < PageSize.Page4K.size()) continue;

            const page_size: PageSize = if (region.len >= PageSize.Page2M.size()) PageSize.Page2M else PageSize.Page4K;
            const page_bytes = page_size.size();

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
