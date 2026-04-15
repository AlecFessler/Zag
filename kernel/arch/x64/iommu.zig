const zag = @import("zag");

const vi = zag.arch.x64.amd.vi;
const vtd = zag.arch.x64.intel.vtd;

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

pub fn mapDmaPages(device: *DeviceRegion, shm: *SharedMemory) !u64 {
    if (active_type == .none) return error.NoIommu;

    // Serialize concurrent mapDmaPages/unmapDmaPages on this device.
    // The `dma_cursor` bump, the leaf-PTE walk+install, and the IOTLB
    // invalidation must all be atomic with respect to other threads
    // holding the same device cap — otherwise two mappers read the
    // same cursor, install overlapping PTEs, and hand two SHMs the
    // same `dma_base`. An unmap of either mapping later tears down
    // the shared leaf PTEs and pmm-frees frames the device is still
    // programmed to DMA into. See exploits/dma_map_race_iova_alias.
    device.detail.pci.dma_lock.lock();
    defer device.detail.pci.dma_lock.unlock();

    const base_dma = device.detail.pci.dma_cursor;
    var i: usize = 0;
    while (i < shm.num_pages) : (i += 1) {
        const dma_addr = base_dma + @as(u64, i) * 0x1000;
        const phys = shm.pageAddr(i);
        switch (active_type) {
            .intel_vtd => try vtd.mapDmaPage(device, dma_addr, phys),
            .amd_vi => try vi.mapDmaPage(device, dma_addr, phys),
            .none => unreachable,
        }
    }
    device.detail.pci.dma_cursor = base_dma + @as(u64, shm.num_pages) * 0x1000;
    switch (active_type) {
        .amd_vi => vi.flushDevice(device),
        .intel_vtd => vtd.invalidateIotlb(),
        .none => {},
    }
    return base_dma;
}

pub fn unmapDmaPages(device: *DeviceRegion, dma_base: u64, num_pages: u64) void {
    // Same per-device lock as mapDmaPages — a concurrent map on this
    // device must not observe partial PTE teardown, and two concurrent
    // unmaps of overlapping ranges (only possible if the map path also
    // raced, but patched here for belt-and-suspenders) must not corrupt
    // the page-table walk.
    device.detail.pci.dma_lock.lock();
    defer device.detail.pci.dma_lock.unlock();

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
