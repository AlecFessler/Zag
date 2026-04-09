const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.9.3 — Device user view `field1` encodes: `pci_vendor(u16) | pci_device(u16) << 16 | pci_class(u8) << 32 | pci_subclass(u8) << 40`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a PCI device and verify all field1 sub-fields decode to valid values.
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            const vendor = view[i].pciVendor();
            if (vendor == 0) continue;

            const device_id = view[i].pciDevice();
            const class_code = view[i].pciClassCode();

            // Cross-check: reconstruct field1 from decoded sub-fields and verify.
            const reconstructed: u64 = @as(u64, vendor) |
                (@as(u64, device_id) << 16) |
                (@as(u64, class_code) << 32) |
                (@as(u64, view[i].pciSubclass()) << 40);
            // Only check the lower 48 bits we reconstructed (upper bits may have bus/dev/func).
            if ((reconstructed & 0xFFFF_FFFF_FFFF) == (view[i].field1 & 0xFFFF_FFFF_FFFF) and device_id > 0) {
                t.pass("§2.9.3");
                syscall.shutdown();
            }
        }
    }
    t.fail("§2.9.3");
    syscall.shutdown();
}
