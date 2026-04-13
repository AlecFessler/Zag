const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.3 — Device user view `field1` encodes: `pci_vendor(u16) | pci_device(u16) << 16 | pci_class(u8) << 32 | pci_subclass(u8) << 40`.
/// Verify the encoding against the known-stable AHCI controller (0x8086/0x2922,
/// pci_class=0x01 subclass=0x06, bus=0 dev=31 func=2).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.4.3");

    const expected_vendor: u16 = 0x8086;
    const expected_device: u16 = 0x2922;
    const expected_class: u8 = 0x01;
    const expected_subclass: u8 = 0x06;
    const expected_bus: u8 = 0;
    const expected_dev_id: u5 = 31;
    const expected_func: u3 = 2;

    // Check the four primary sub-fields directly against known values (not via
    // reconstruction): the bit offsets in the spec are what is being tested.
    if (dev.pciVendor() != expected_vendor) {
        t.failWithVal("§2.4.3 vendor", expected_vendor, dev.pciVendor());
        syscall.shutdown();
    }
    if (dev.pciDevice() != expected_device) {
        t.failWithVal("§2.4.3 device", expected_device, dev.pciDevice());
        syscall.shutdown();
    }
    if (dev.pciClassCode() != expected_class) {
        t.failWithVal("§2.4.3 class", expected_class, dev.pciClassCode());
        syscall.shutdown();
    }
    if (dev.pciSubclass() != expected_subclass) {
        t.failWithVal("§2.4.3 subclass", expected_subclass, dev.pciSubclass());
        syscall.shutdown();
    }

    // Also cross-check the raw bit layout: reconstruct the low 48 bits of
    // field1 from the known values and compare.
    const expected_low48: u64 = @as(u64, expected_vendor) |
        (@as(u64, expected_device) << 16) |
        (@as(u64, expected_class) << 32) |
        (@as(u64, expected_subclass) << 40);
    if ((dev.field1 & 0xFFFF_FFFF_FFFF) != expected_low48) {
        t.failWithVal("§2.4.3 raw_f1", @bitCast(expected_low48), @bitCast(dev.field1 & 0xFFFF_FFFF_FFFF));
        syscall.shutdown();
    }

    // Sanity: bus/dev/func accessors are consistent with the known BDF.
    if (dev.pciBus() != expected_bus or dev.pciDev() != expected_dev_id or dev.pciFunc() != expected_func) {
        t.fail("§2.4.3 bdf");
        syscall.shutdown();
    }

    t.pass("§2.4.3");
    syscall.shutdown();
}
