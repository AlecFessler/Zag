const std = @import("std");

const bootalloc = @import("boot_allocator.zig");
const multiboot = @import("../arch/x86_64/multiboot.zig");

const BootAllocator = bootalloc.BootAllocator;
const MemoryRegionType = multiboot.MemoryRegionType;
const num_region_types = @typeInfo(MemoryRegionType).@"enum".fields.len;
const max_regions_per_type = 16;

const MemoryRegion = struct {
    addr: u64,
    len: u64,
    region_type: MemoryRegionType,
};

pub const RegionAllocator = struct {
    /// Only regions with the .Available type will be allocated, but all regions are tracked
    regions: [num_region_types][max_regions_per_type]MemoryRegion,
    counts: [num_region_types]usize,

    pub fn init() RegionAllocator {
        return RegionAllocator{
            .regions = undefined,
            .counts = .{0} ** num_region_types,
        };
    }

    /// This interface must match the multiboot.parseMemoryMap callback function interface
    pub fn append_region(ctx: *anyopaque, addr: u64, len: u64, region_type: MemoryRegionType) void {
        const self: *RegionAllocator = @alignCast(@ptrCast(ctx));
        const type_index = @intFromEnum(region_type);
        const type_count = self.counts[type_index];

        if (type_count >= max_regions_per_type) @panic("RegionAllocator: too many regions of a given type!");

        self.regions[type_index][type_count] = MemoryRegion{
            .addr = addr,
            .len = len,
            .region_type = region_type,
        };
        self.counts[type_index] += 1;
    }
};
