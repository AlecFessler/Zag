const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.4 — At boot, the kernel inserts all device handles into the root service's permissions table.
/// The test rig (QEMU q35) registers a known set of devices; verify every expected
/// device actually appears in the root service's user view.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // All four expected devices must be present. requireDevice aborts if any
    // are missing.
    _ = t.requireDevice(view, "§2.5.4 ahci_mmio", t.AHCI_VENDOR, t.AHCI_DEVICE, 0);
    _ = t.requireDevice(view, "§2.5.4 ahci_pio", t.AHCI_VENDOR, t.AHCI_DEVICE, 1);
    _ = t.requireDevice(view, "§2.5.4 bochs_mmio", t.BOCHS_VENDOR, t.BOCHS_DEVICE, 0);

    // Also check at least one PIO device is exposed (SMBus 0x8086/0x2930).
    _ = t.requireDevice(view, "§2.5.4 smbus_pio", 0x8086, 0x2930, 1);

    t.pass("§2.5.4");
    syscall.shutdown();
}
