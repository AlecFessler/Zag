const std = @import("std");
const zag = @import("zag");

const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;

const PAddr = zag.memory.address.PAddr;

pub const DeviceRegion = struct {
    phys_base: PAddr,
    size: u64,
};

const DeviceRegionSlab = SlabAllocator(DeviceRegion, false, 0, 32);

var device_region_slab: DeviceRegionSlab = undefined;
var slab_initialized = false;

pub fn initSlab(backing: std.mem.Allocator) !void {
    device_region_slab = try DeviceRegionSlab.init(backing);
    slab_initialized = true;
}

pub fn create(phys_base: PAddr, size: u64) !*DeviceRegion {
    std.debug.assert(slab_initialized);
    const dr = try device_region_slab.allocator().create(DeviceRegion);
    dr.* = .{ .phys_base = phys_base, .size = size };
    return dr;
}

pub fn destroy(dr: *DeviceRegion) void {
    device_region_slab.allocator().destroy(dr);
}
