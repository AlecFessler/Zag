const memory = @import("memory");
const PAddr = memory.address.PAddr;

pub const DeviceType = enum(u8) { mmio = 0, port_io = 1 };
pub const DeviceClass = enum(u8) { network = 0, serial = 1, storage = 2, display = 3, timer = 4, usb = 5, unknown = 0xFF };

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
