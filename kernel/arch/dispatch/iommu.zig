const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const SharedMemory = zag.memory.shared.SharedMemory;

pub fn isDmaRemapAvailable() bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.iommu.isAvailable(),
        .aarch64 => aarch64.iommu.isAvailable(),
        else => unreachable,
    };
}

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
