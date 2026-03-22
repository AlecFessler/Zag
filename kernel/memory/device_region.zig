const std = @import("std");
const zag = @import("zag");

const PAddr = zag.memory.address.PAddr;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;

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

pub const DeviceRegion = struct {
    phys_base: PAddr,
    size: u64,
    base_port: u16,
    port_count: u16,
    device_type: DeviceType,
    device_class: DeviceClass,
    pci_vendor: u16,
    pci_device: u16,
    pci_class: u8,
    pci_subclass: u8,
};

const DeviceRegionSlab = SlabAllocator(DeviceRegion, false, 0, 32);

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
) !*DeviceRegion {
    std.debug.assert(slab_initialized);
    const dr = try device_region_slab.allocator().create(DeviceRegion);
    dr.* = .{
        .phys_base = phys_base,
        .size = size,
        .base_port = 0,
        .port_count = 0,
        .device_type = .mmio,
        .device_class = device_class,
        .pci_vendor = pci_vendor,
        .pci_device = pci_device,
        .pci_class = pci_class,
        .pci_subclass = pci_subclass,
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
) !*DeviceRegion {
    std.debug.assert(slab_initialized);
    const dr = try device_region_slab.allocator().create(DeviceRegion);
    dr.* = .{
        .phys_base = PAddr.fromInt(0),
        .size = 0,
        .base_port = base_port,
        .port_count = port_count,
        .device_type = .port_io,
        .device_class = device_class,
        .pci_vendor = pci_vendor,
        .pci_device = pci_device,
        .pci_class = pci_class,
        .pci_subclass = pci_subclass,
    };
    return dr;
}

pub fn destroy(dr: *DeviceRegion) void {
    device_region_slab.allocator().destroy(dr);
}
