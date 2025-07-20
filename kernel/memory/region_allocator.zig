const std = @import("std");

// NOTE: DEBUG
const console = @import("../console.zig");

const allocator_interface = @import("allocator.zig");
const multiboot = @import("../arch/x86_64/multiboot.zig");
const paging = @import("paging.zig");

const Allocator = allocator_interface.Allocator;
const MemoryRegionType = multiboot.MemoryRegionType;

const num_region_types = @typeInfo(MemoryRegionType).@"enum".fields.len;
const max_regions = 32;
const page_size = 4096;

const MemoryRegion = struct {
    addr: u64,
    len: u64,
    region_type: MemoryRegionType,
};

pub const RegionAllocator = struct {
    /// Only regions with the .Available type will be allocated, but all regions are tracked
    regions: [max_regions]MemoryRegion,
    count: usize = 0,
    allocator: *Allocator,

    pub fn init(allocator: *Allocator) RegionAllocator {
        return RegionAllocator{ .regions = undefined, .count = 0, .allocator = allocator };
    }

    /// This interface must match the multiboot.parseMemoryMap callback function interface.
    /// It must be ensured that the caller is not making allocations using the boot allocator
    /// in between calls to this function, or else the allocations this makes will not be contiguous.
    /// This allocation restriction starts as soon as this is struct is initialized as it grabs the
    /// base the allocator will pass on the next allocation by requesting a 0 size allocation.
    pub fn append_region(ctx: *anyopaque, addr: u64, len: u64, region_type: MemoryRegionType) void {
        const self: *RegionAllocator = @alignCast(@ptrCast(ctx));

        self.regions[self.count] = MemoryRegion{
            .addr = addr,
            .len = len,
            .region_type = region_type,
        };
        self.count += 1;
    }

    pub fn initialize_page_tables(self: *RegionAllocator, base_vaddr: usize) void {
        const pml4 = self.allocator.alloc(page_size, page_size);
        for (self.regions) |region| {
            const region_end = region.addr + region.len;
            var paddr = region.addr;
            var vaddr = base_vaddr + region.addr;
            const rw: paging.RW = if (region.region_type == .Available) .ReadWrite else .Readonly;

            // NOTE: DEBUG
            console.print("Mapping region: addr {}, len {}, type {s}\n", .{ region.addr, region.len, region.region_type.toString() });

            while (paddr < region_end) {
                paging.mapPage(@alignCast(@ptrCast(pml4)), paddr, vaddr, rw, .Supervisor, self.allocator);
                paddr += page_size;
                vaddr += page_size;
            }
        }
    }
};
