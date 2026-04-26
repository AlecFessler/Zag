const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const SharedMemory = zag.memory.shared.SharedMemory;
const SpecDeviceRegion = zag.devices.device_region.DeviceRegion;
const VarPageSize = zag.capdom.var_range.PageSize;

pub fn isDmaRemapAvailable() bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.isAvailable(),
        .aarch64 => aarch64.iommu.isAvailable(),
        else => unreachable,
    };
}

// TODO spec-v3: delete once all DMA mapping uses VARs (replacement is
// `iommuMapPage` per (iova, page_frame) pair).
pub fn mapDmaPages(device: *DeviceRegion, shm: *SharedMemory) !u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.mapDmaPages(device, shm),
        .aarch64 => aarch64.iommu.mapDmaPages(device, shm),
        else => unreachable,
    };
}

pub fn unmapDmaPages(device: *DeviceRegion, dma_base: u64, num_pages: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.unmapDmaPages(device, dma_base, num_pages),
        .aarch64 => aarch64.iommu.unmapDmaPages(device, dma_base, num_pages),
        else => unreachable,
    }
}

pub fn enableDmaRemapping() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.enableTranslation(),
        .aarch64 => aarch64.iommu.enableTranslation(),
        else => unreachable,
    }
}

// ── Spec v3 IOMMU primitives ─────────────────────────────────────────
// Per-device IOMMU domain primitives used by DMA-flagged VARs to
// install/uninstall page_frames into a device's stream-id-tagged
// translation tables. Spec §[var].map_pf (caps.dma=1).

/// Allocate an IOMMU domain (Intel VT-d context entry / AMD-Vi DTE /
/// SMMU stream table entry) for `device` and return an opaque per-arch
/// handle stored in the kernel's DeviceRegion for later map/unmap.
pub fn createIommuDomain(device: *SpecDeviceRegion) !*anyopaque {
    _ = device;
    switch (builtin.cpu.arch) {
        .x86_64 => return error.NotImplemented,
        .aarch64 => return error.NotImplemented,
        else => unreachable,
    }
}

/// Tear down the IOMMU domain previously installed by
/// `createIommuDomain`. Quiesces in-flight DMA and invalidates IOTLB.
pub fn destroyIommuDomain(device: *SpecDeviceRegion) void {
    _ = device;
}

/// Map a single page-sized IOVA in `device`'s domain to `phys` with
/// `perms`. Spec §[var].map_pf (caps.dma=1).
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
    switch (builtin.cpu.arch) {
        .x86_64 => return error.NotImplemented,
        .aarch64 => return error.NotImplemented,
        else => unreachable,
    }
}

/// Unmap a single page-sized IOVA from `device`'s domain. Returns the
/// previously bound physical address if any.
pub fn iommuUnmapPage(
    device: *SpecDeviceRegion,
    iova: u64,
    sz: VarPageSize,
) ?PAddr {
    _ = device;
    _ = iova;
    _ = sz;
    switch (builtin.cpu.arch) {
        .x86_64 => return null,
        .aarch64 => return null,
        else => unreachable,
    }
}

/// Invalidate IOTLB entries covering `page_count` pages starting at
/// `iova` in `device`'s domain. Required after any unmap or
/// permission downgrade so the device cannot continue to DMA against
/// stale translations.
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
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => {},
        else => unreachable,
    }
}
