const zag = @import("zag");

const vtd = @import("intel/vtd.zig");
const vi = @import("amd/vi.zig");

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const PAddr = zag.memory.address.PAddr;
const SharedMemory = zag.memory.shared.SharedMemory;

const IommuType = enum {
    none,
    intel_vtd,
    amd_vi,
};

var active_type: IommuType = .none;

pub fn initIntel(reg_base: PAddr) !void {
    try vtd.init(reg_base);
    active_type = .intel_vtd;
}

pub fn initAmd(reg_base: PAddr) !void {
    try vi.init(reg_base);
    active_type = .amd_vi;
}

pub fn setupDevice(device: *DeviceRegion) !void {
    switch (active_type) {
        .intel_vtd => try vtd.setupDevice(device),
        .amd_vi => try vi.setupDevice(device),
        .none => {},
    }
}

pub fn mapDmaPages(device: *DeviceRegion, shm: *SharedMemory) !u64 {
    if (active_type == .none) return error.NoIommu;

    const base_dma = device.dma_cursor;
    for (shm.pages, 0..) |phys, i| {
        const dma_addr = base_dma + @as(u64, i) * 0x1000;
        switch (active_type) {
            .intel_vtd => try vtd.mapDmaPage(device, dma_addr, phys),
            .amd_vi => try vi.mapDmaPage(device, dma_addr, phys),
            .none => unreachable,
        }
    }
    device.dma_cursor = base_dma + @as(u64, shm.pages.len) * 0x1000;
    if (active_type == .amd_vi) {
        vi.flushAll();
    }
    return base_dma;
}

pub fn unmapDmaPages(device: *DeviceRegion, dma_base: u64, num_pages: u64) void {
    var i: u64 = 0;
    while (i < num_pages) : (i += 1) {
        const dma_addr = dma_base + i * 0x1000;
        switch (active_type) {
            .intel_vtd => vtd.unmapDmaPage(device, dma_addr),
            .amd_vi => vi.unmapDmaPage(device, dma_addr),
            .none => {},
        }
    }
}

pub fn isAvailable() bool {
    return active_type != .none;
}

pub fn typeName() []const u8 {
    return switch (active_type) {
        .intel_vtd => "Intel VT-d",
        .amd_vi => "AMD-Vi",
        .none => "none",
    };
}
