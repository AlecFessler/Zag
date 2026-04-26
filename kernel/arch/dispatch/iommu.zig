const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const DeviceRegion = zag.devices.device_region.DeviceRegion;
const PAddr = zag.memory.address.PAddr;
const VarPageSize = zag.capdom.var_range.PageSize;

// `zag.perms.memory.MemoryPerms` was removed in spec v3. Until a v3
// home for it lands, define the minimum shape the IOMMU map path
// needs locally so the per-arch backings can match against fields
// without a cross-tree import.
pub const MemoryPerms = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    exec: bool = false,
    _reserved: u5 = 0,
};

pub fn isDmaRemapAvailable() bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.isAvailable(),
        .aarch64 => aarch64.iommu.isAvailable(),
        else => unreachable,
    };
}

pub fn enableDmaRemapping() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.enableTranslation(),
        .aarch64 => aarch64.iommu.enableTranslation(),
        else => unreachable,
    }
}

/// Allocate an IOMMU domain (Intel VT-d context entry / AMD-Vi DTE /
/// SMMU stream table entry) for `device` and return an opaque per-arch
/// handle stored in the kernel's DeviceRegion for later map/unmap.
/// Spec §[var].map_pf (caps.dma=1).
pub fn createIommuDomain(device: *DeviceRegion) !*anyopaque {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.iommu.createIommuDomain(device),
        .aarch64 => return aarch64.iommu.createIommuDomain(device),
        else => unreachable,
    }
}

/// Tear down the IOMMU domain previously installed by
/// `createIommuDomain`. Quiesces in-flight DMA and invalidates IOTLB.
pub fn destroyIommuDomain(device: *DeviceRegion) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.destroyIommuDomain(device),
        .aarch64 => aarch64.iommu.destroyIommuDomain(device),
        else => unreachable,
    }
}

/// Map a single page-sized IOVA in `device`'s domain to `phys` with
/// `perms`. Spec §[var].map_pf (caps.dma=1).
pub fn iommuMapPage(
    device: *DeviceRegion,
    iova: u64,
    phys: PAddr,
    sz: VarPageSize,
    perms: MemoryPerms,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.iommu.iommuMapPage(device, iova, phys, sz, perms),
        .aarch64 => return aarch64.iommu.iommuMapPage(device, iova, phys, sz, perms),
        else => unreachable,
    }
}

/// Unmap a single page-sized IOVA from `device`'s domain. Returns the
/// previously bound physical address if any.
pub fn iommuUnmapPage(
    device: *DeviceRegion,
    iova: u64,
    sz: VarPageSize,
) ?PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.iommu.iommuUnmapPage(device, iova, sz),
        .aarch64 => return aarch64.iommu.iommuUnmapPage(device, iova, sz),
        else => unreachable,
    }
}

/// Invalidate IOTLB entries covering `page_count` pages starting at
/// `iova` in `device`'s domain. Required after any unmap or
/// permission downgrade so the device cannot continue to DMA against
/// stale translations.
pub fn invalidateIotlbRange(
    device: *DeviceRegion,
    iova: u64,
    sz: VarPageSize,
    page_count: u32,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.invalidateIotlbRange(device, iova, sz, page_count),
        .aarch64 => aarch64.iommu.invalidateIotlbRange(device, iova, sz, page_count),
        else => unreachable,
    }
}
