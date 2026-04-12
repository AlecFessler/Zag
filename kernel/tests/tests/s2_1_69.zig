const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.69 — `device_region` entry: `field0` and `field1` follow §2.9 encoding.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region entry and verify field0/field1 encoding by decoding
    // all sub-fields and checking structural consistency.
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            const entry = &view[i];
            // §2.9.2: field0 = device_type(u8) | device_class(u8)<<8 | size_or_port_count(u32)<<32
            const device_type = entry.deviceType();
            const size = entry.deviceSizeOrPortCount();
            // §2.9.3: field1 = pci_vendor(u16) | pci_device(u16)<<16 | pci_class(u8)<<32 | pci_subclass(u8)<<40
            const vendor = entry.pciVendor();
            const device_id = entry.pciDevice();
            // Verify: valid device_type (0=mmio, 1=port_io), non-zero size,
            // non-zero vendor and device ID (real PCI devices have these).
            if ((device_type == 0 or device_type == 1) and size > 0 and vendor > 0 and device_id > 0) {
                // Cross-check: reconstruct field0 lower bits and verify they match.
                const reconstructed_type: u8 = @truncate(entry.field0);
                if (reconstructed_type == device_type) {
                    t.pass("§2.1.69");
                    syscall.shutdown();
                }
            }
        }
    }
    t.fail("§2.1.69");
    syscall.shutdown();
}
