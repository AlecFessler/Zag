const zag = @import("zag");

const device_region_mod = zag.memory.device_region;

const DeviceClass = zag.memory.device_region.DeviceClass;
const DeviceRegion = zag.memory.device_region.DeviceRegion;
const Framebuffer = zag.boot.protocol.Framebuffer;
const PAddr = zag.memory.address.PAddr;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Process = zag.proc.process.Process;

const MAX_DEVICES = 128;

var device_table: [MAX_DEVICES]*DeviceRegion = undefined;
var device_count: u32 = 0;

pub fn registerMmioDevice(
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
    if (device_count >= MAX_DEVICES) return error.TooManyDevices;
    const dr = try device_region_mod.createMmio(
        phys_base,
        size,
        device_class,
        pci_vendor,
        pci_device,
        pci_class,
        pci_subclass,
        pci_bus,
        pci_dev,
        pci_func,
    );
    device_table[device_count] = dr;
    device_count += 1;
    return dr;
}

pub fn registerPortIoDevice(
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
    if (device_count >= MAX_DEVICES) return error.TooManyDevices;
    const dr = try device_region_mod.createPortIo(
        base_port,
        port_count,
        device_class,
        pci_vendor,
        pci_device,
        pci_class,
        pci_subclass,
        pci_bus,
        pci_dev,
        pci_func,
    );
    device_table[device_count] = dr;
    device_count += 1;
    return dr;
}

pub fn registerDisplayDevice(fb: Framebuffer) void {
    if (fb.pixel_format == .none or fb.base.addr == 0) return;
    if (device_count >= MAX_DEVICES) return;
    const dr = device_region_mod.createDisplay(
        fb.base,
        fb.size,
        @intCast(fb.width),
        @intCast(fb.height),
        @intCast(fb.stride),
        @intFromEnum(fb.pixel_format),
    ) catch return;
    device_table[device_count] = dr;
    device_count += 1;
}

pub fn grantAllToRootService(root_proc: *Process) void {
    var i: u32 = 0;
    while (i < device_count) : (i += 1) {
        const entry = PermissionEntry{
            .handle = 0,
            .object = .{ .device_region = device_table[i] },
            .rights = 0b1111,
        };
        _ = root_proc.insertPerm(entry) catch {};
    }
}

pub fn count() u32 {
    return device_count;
}

pub fn getDevice(index: u32) ?*DeviceRegion {
    if (index >= device_count) return null;
    return device_table[index];
}
