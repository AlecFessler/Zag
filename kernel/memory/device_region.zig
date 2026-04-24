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

fn allocRegion() !*DeviceRegion {
    std.debug.assert(slab_initialized);
    const r = try device_region_slab.create();
    return r.ptr;
}

/// Zero the union storage before writing the active variant. Without
/// this, a recycled slot keeps the previous occupant's Pci tail bytes
/// (Pci is larger than Display) leaking through the union. Same story
/// for the outer DeviceRegion `_pad`.
fn zeroRegionBytes(dr: *DeviceRegion) void {
    const base: [*]u8 = @ptrCast(dr);
    const gen_lock_off: usize = @offsetOf(DeviceRegion, "_gen_lock");
    const gen_lock_size: usize = @sizeOf(@TypeOf(dr._gen_lock));
    // Zero everything except the gen-lock word — that was just set by
    // the allocator and must not be clobbered.
    @memset(base[0..gen_lock_off], 0);
    @memset(base[gen_lock_off + gen_lock_size .. @sizeOf(DeviceRegion)], 0);
}

pub fn createMmio(
    phys_base: PAddr,
    size: u64,
    device_class: DeviceClass,
    pci_vendor: u16,
    pci_device: u16,
    pci_class: u8,
    pci_subclass: u8,
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
) !*DeviceRegion {
    const dr = try allocRegion();
    zeroRegionBytes(dr);
    dr.access = .{ .mmio = .{ .phys_base = phys_base, .size = size } };
    dr.detail = .{ .pci = .{
        .vendor = pci_vendor,
        .device = pci_device,
        .class = pci_class,
        .subclass = pci_subclass,
        .bus = pci_bus,
        .dev = pci_dev,
        .func = pci_func,
        .dma_page_table_root = PAddr.fromInt(0),
        .dma_cursor = 0x1000,
    } };
    dr.device_type = .mmio;
    dr.device_class = device_class;
    return dr;
}

pub fn createPortIo(
    base_port: u16,
    port_count: u16,
    device_class: DeviceClass,
    pci_vendor: u16,
    pci_device: u16,
    pci_class: u8,
    pci_subclass: u8,
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
) !*DeviceRegion {
    const dr = try allocRegion();
    zeroRegionBytes(dr);
    dr.access = .{ .port_io = .{ .base_port = base_port, .port_count = port_count } };
    dr.detail = .{ .pci = .{
        .vendor = pci_vendor,
        .device = pci_device,
        .class = pci_class,
        .subclass = pci_subclass,
        .bus = pci_bus,
        .dev = pci_dev,
        .func = pci_func,
        .dma_page_table_root = PAddr.fromInt(0),
        .dma_cursor = 0,
    } };
    dr.device_type = .port_io;
    dr.device_class = device_class;
    return dr;
}

pub fn createDisplay(
    phys_base: PAddr,
    size: u64,
    fb_width: u16,
    fb_height: u16,
    fb_stride: u16,
    fb_pixel_format: u8,
) !*DeviceRegion {
    const dr = try allocRegion();
    zeroRegionBytes(dr);
    dr.access = .{ .mmio = .{ .phys_base = phys_base, .size = size } };
    dr.detail = .{ .display = .{
        .fb_width = fb_width,
        .fb_height = fb_height,
        .fb_stride = fb_stride,
        .fb_pixel_format = fb_pixel_format,
    } };
    dr.device_type = .mmio;
    dr.device_class = .display;
    return dr;
}
