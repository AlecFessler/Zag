const std = @import("std");
const zag = @import("zag");

const PAddr = zag.memory.address.PAddr;
const SlabAllocator = zag.memory.allocators.slab.SlabAllocator;

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

pub const Pci = struct {
    vendor: u16,
    device: u16,
    class: u8,
    subclass: u8,
    bus: u8,
    dev: u8,
    func: u8,
    dma_page_table_root: PAddr,
    dma_cursor: u64,
};

pub const Display = struct {
    fb_width: u16,
    fb_height: u16,
    fb_stride: u16,
    fb_pixel_format: u8,
};

pub const DeviceRegion = struct {
    device_type: DeviceType,
    device_class: DeviceClass,

    access: union {
        mmio: struct { phys_base: PAddr, size: u64 },
        port_io: struct { base_port: u16, port_count: u16 },
    },

    detail: union {
        pci: Pci,
        display: Display,
        none: void,
    },
};

const DeviceRegionSlab = SlabAllocator(DeviceRegion, false, 0, 32, true);

var device_region_slab: DeviceRegionSlab = undefined;
var slab_initialized = false;

pub fn initSlab(backing: std.mem.Allocator) !void {
    device_region_slab = try DeviceRegionSlab.init(backing);
    slab_initialized = true;
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
    std.debug.assert(slab_initialized);
    const dr = try device_region_slab.allocator().create(DeviceRegion);
    dr.* = .{
        .device_type = .mmio,
        .device_class = device_class,
        .access = .{ .mmio = .{ .phys_base = phys_base, .size = size } },
        .detail = .{ .pci = .{
            .vendor = pci_vendor,
            .device = pci_device,
            .class = pci_class,
            .subclass = pci_subclass,
            .bus = pci_bus,
            .dev = pci_dev,
            .func = pci_func,
            .dma_page_table_root = PAddr.fromInt(0),
            .dma_cursor = 0x1000,
        } },
    };
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
    std.debug.assert(slab_initialized);
    const dr = try device_region_slab.allocator().create(DeviceRegion);
    dr.* = .{
        .device_type = .port_io,
        .device_class = device_class,
        .access = .{ .port_io = .{ .base_port = base_port, .port_count = port_count } },
        .detail = .{ .pci = .{
            .vendor = pci_vendor,
            .device = pci_device,
            .class = pci_class,
            .subclass = pci_subclass,
            .bus = pci_bus,
            .dev = pci_dev,
            .func = pci_func,
            .dma_page_table_root = PAddr.fromInt(0),
            .dma_cursor = 0,
        } },
    };
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
    std.debug.assert(slab_initialized);
    const dr = try device_region_slab.allocator().create(DeviceRegion);
    dr.* = .{
        .device_type = .mmio,
        .device_class = .display,
        .access = .{ .mmio = .{ .phys_base = phys_base, .size = size } },
        .detail = .{ .display = .{
            .fb_width = fb_width,
            .fb_height = fb_height,
            .fb_stride = fb_stride,
            .fb_pixel_format = fb_pixel_format,
        } },
    };
    return dr;
}

pub fn destroy(dr: *DeviceRegion) void {
    device_region_slab.allocator().destroy(dr);
}
