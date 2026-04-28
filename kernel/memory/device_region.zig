const std = @import("std");
const zag = @import("zag");

const secure_slab = zag.memory.allocators.secure_slab;

const GenLock = secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const SecureSlab = secure_slab.SecureSlab;

pub const DeviceType = enum(u8) {
    mmio = 0,
    port_io = 1,
};

pub const DeviceClass = enum(u8) {
    network = 0,
    serial = 1,
    storage = 2,
    display = 3,
    timer = 4,
    usb = 5,
    unknown = 0xFF,
};

pub const AccessMmio = extern struct {
    phys_base: PAddr,
    size: u64,
};

pub const AccessPortIo = extern struct {
    base_port: u16,
    port_count: u16,
    _pad: [4]u8 = .{ 0, 0, 0, 0 },
    // Padded to match AccessMmio's 16-byte footprint so the enclosing
    // extern union has a deterministic size regardless of the variant.
    _pad2: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

pub const Access = extern union {
    mmio: AccessMmio,
    port_io: AccessPortIo,
};

pub const Pci = extern struct {
    vendor: u16,
    device: u16,
    class: u8,
    subclass: u8,
    bus: u8,
    dev: u8,
    func: u8,
    _pad: [3]u8 = .{ 0, 0, 0 },
    dma_page_table_root: PAddr,
    dma_cursor: u64,
};

pub const Display = extern struct {
    fb_width: u16,
    fb_height: u16,
    fb_stride: u16,
    fb_pixel_format: u8,
    _pad: [1]u8 = .{0},
};

pub const Detail = extern union {
    pci: Pci,
    display: Display,
};

/// DMA-path mutual exclusion for a DeviceRegion comes from the object's
/// own `_gen_lock` (SecureSlab). Without that, two threads sharing a
/// device cap with the `dma` right could race in the iommu walk, read
/// the same `dma_cursor`, install overlapping leaf PTEs, and return the
/// same `dma_base` for two different SHMs — see
/// exploits/dma_map_race_iova_alias. The old `Pci.dma_lock` is gone;
/// callers on `mapDmaPages` / `unmapDmaPages` acquire `dr._gen_lock`.
pub const DeviceRegion = extern struct {
    _gen_lock: GenLock = .{},
    access: Access,
    detail: Detail,
    device_type: DeviceType,
    device_class: DeviceClass,
    _pad: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
};

const DeviceRegionSlab = SecureSlab(DeviceRegion, 256);

var device_region_slab: DeviceRegionSlab = undefined;
var slab_initialized = false;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    device_region_slab = DeviceRegionSlab.init(data_range, ptrs_range, links_range);
    slab_initialized = true;
}

// Slot allocation helpers (allocRegion / zeroRegionBytes) lived here for
// the old createMmio / createPortIo / createDisplay constructors that
// have since been removed. They will be reinstated when device_region
// minting lands on the spec-v3 syscall surface.
//
// Reuse cleaner: zero the union storage before writing the active variant.
// Without this, a recycled slot keeps the previous occupant's Pci tail
// bytes (Pci is larger than Display) leaking through the union. Same
// story for the outer DeviceRegion `_pad`. Keep the tail of zeroRegionBytes
// here as a comment until the constructor flow is rebuilt:
