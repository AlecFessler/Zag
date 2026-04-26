const std = @import("std");
const zag = @import("zag");

const dispatch_iommu = zag.arch.dispatch.iommu;
const vi = zag.arch.x64.amd.vi;
const vtd = zag.arch.x64.intel.vtd;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const SpecDeviceRegion = zag.devices.device_region.DeviceRegion;
const VarPageSize = zag.capdom.var_range.PageSize;

const IommuType = enum {
    none,
    intel_vtd,
    amd_vi,
};

var active_type: IommuType = .none;

pub fn initIntel(reg_base: PAddr) !void {
    // Invariant: at most one IOMMU flavor per platform; ACPI calls this
    // serially during boot, so no lock is required.
    std.debug.assert(active_type == .none);
    try vtd.init(reg_base);
    active_type = .intel_vtd;
}

pub fn initAmd(reg_base: PAddr) !void {
    // Invariant: at most one IOMMU flavor per platform; ACPI calls this
    // serially during boot, so no lock is required.
    std.debug.assert(active_type == .none);
    try vi.init(reg_base);
    active_type = .amd_vi;
}

pub fn addAmdAlias(source: u16, alias: u16) void {
    vi.addAlias(source, alias);
}

pub fn setupDevice(device: *DeviceRegion) !void {
    switch (active_type) {
        .intel_vtd => try vtd.setupDevice(device),
        .amd_vi => try vi.setupDevice(device),
        .none => {},
    }
}

/// Call after all setupDevice calls to enable translation.
/// For Intel VT-d, TE is deferred from init to avoid caching
/// "not present" entries before context entries are populated.
pub fn enableTranslation() void {
    switch (active_type) {
        .intel_vtd => vtd.enableTranslation(),
        .amd_vi => vi.enableTranslation(),
        .none => {},
    }
}

pub fn mapDmaPages(device: *DeviceRegion, frame: *PageFrame) !u64 {
    if (active_type == .none) return error.NoIommu;

    // Serialize concurrent mapDmaPages/unmapDmaPages on this device via
    // the DeviceRegion's own gen-lock. The `dma_cursor` bump, the
    // leaf-PTE walk+install, and the IOTLB invalidation must all be
    // atomic with respect to other threads holding the same device cap
    // — otherwise two mappers read the same cursor, install overlapping
    // PTEs, and hand two frames the same `dma_base`, then an unmap of
    // either mapping tears down shared leaf PTEs and pmm-frees frames
    // the device is still DMAing into. See
    // exploits/dma_map_race_iova_alias.
    device._gen_lock.lock(@src());
    defer device._gen_lock.unlock();
    frame._gen_lock.lock(@src());
    defer frame._gen_lock.unlock();

    const base_dma = device.detail.pci.dma_cursor;
    var i: usize = 0;
    while (i < frame.num_pages) : (i += 1) {
        const dma_addr = base_dma + @as(u64, i) * 0x1000;
        const phys = frame.pageAddr(i);
        switch (active_type) {
            .intel_vtd => try vtd.mapDmaPage(device, dma_addr, phys),
            .amd_vi => try vi.mapDmaPage(device, dma_addr, phys),
            .none => unreachable,
        }
    }
    device.detail.pci.dma_cursor = base_dma + @as(u64, frame.num_pages) * 0x1000;
    switch (active_type) {
        .amd_vi => vi.flushDevice(device),
        .intel_vtd => vtd.invalidateIotlb(),
        .none => {},
    }
    return base_dma;
}

pub fn unmapDmaPages(device: *DeviceRegion, dma_base: u64, num_pages: u64) void {
    // Same per-device gen-lock as mapDmaPages.
    device._gen_lock.lock(@src());
    defer device._gen_lock.unlock();

    var i: u64 = 0;
    while (i < num_pages) {
        const dma_addr = dma_base + i * 0x1000;
        switch (active_type) {
            .intel_vtd => vtd.unmapDmaPage(device, dma_addr),
            .amd_vi => vi.unmapDmaPage(device, dma_addr),
            .none => {},
        }
        i += 1;
    }
    switch (active_type) {
        .amd_vi => vi.flushDevice(device),
        .intel_vtd => vtd.invalidateIotlb(),
        .none => {},
    }
}

pub fn isAvailable() bool {
    return active_type != .none;
}

pub fn createIommuDomain(device: *SpecDeviceRegion) !*anyopaque {
    _ = device;
    @panic("not implemented");
}

pub fn destroyIommuDomain(device: *SpecDeviceRegion) void {
    _ = device;
    @panic("not implemented");
}

pub fn iommuMapPage(
    device: *SpecDeviceRegion,
    iova: u64,
    phys: PAddr,
    sz: VarPageSize,
    perms: MemoryPerms,
) !void {
    _ = device;
    _ = iova;
    _ = phys;
    _ = sz;
    _ = perms;
    @panic("not implemented");
}

pub fn iommuUnmapPage(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VarPageSize,
) ?PAddr {
    _ = device;
    _ = iova;
    _ = sz;
    @panic("not implemented");
}

pub fn invalidateIotlbRange(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VarPageSize,
    page_count: u32,
) void {
    _ = device;
    _ = iova;
    _ = sz;
    _ = page_count;
    @panic("not implemented");
}
