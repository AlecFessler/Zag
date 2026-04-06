const memory = @import("memory");
const PAddr = memory.address.PAddr;

pub const DeviceType = enum(u8) { mmio = 0, port_io = 1 };
pub const DeviceClass = enum(u8) { network = 0, serial = 1, storage = 2, display = 3, timer = 4, usb = 5, unknown = 0xFF };

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
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    dma_page_table_root: PAddr,
    dma_cursor: u64,
};
