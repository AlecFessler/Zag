const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.5 — Kernel-internal devices (platform timer, interrupt controller) are not exposed in the user view.
/// The kernel owns the platform timer (x86: HPET at 0xFED00000; ARM: arch timer)
/// and the interrupt controller (x86: LAPIC@0xFEE00000 + IOAPIC@0xFEC00000;
/// ARM: GICv2/v3). None of these are PCI devices — they should never
/// appear in the root service's device table. Check both by device_class
/// (nothing marked `timer`) and by PCI identification (no entry with vendor=0
/// AND device=0 except the legacy 8250 serial, which IS expected).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Sanity: the test rig must actually have some device entries. If not,
    // inventory is broken — fail hard.
    _ = t.requireMmioDevice(view, "§2.4.5 baseline");

    var saw_any_device = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        saw_any_device = true;

        // (a) No kernel-internal timer should leak through as a device entry.
        if (e.deviceClass() == @intFromEnum(perms.DeviceClass.timer)) {
            t.fail("§2.4.5 timer_exposed");
            syscall.shutdown();
        }

        // (b) Every exposed entry must have a non-zero size.
        if (e.deviceSizeOrPortCount() == 0) {
            t.fail("§2.4.5 zero_size");
            syscall.shutdown();
        }

        // (c) No known fixed-address kernel device. We can't read the physical
        //     address from userspace, but any device with `serial` class and
        //     zero PCI IDs is the legacy COM port (allowed). Everything else
        //     with zero PCI IDs would be suspicious.
        const zero_pci = e.pciVendor() == 0 and e.pciDevice() == 0;
        const is_legacy_serial = e.deviceClass() == @intFromEnum(perms.DeviceClass.serial);
        if (zero_pci and !is_legacy_serial) {
            t.fail("§2.4.5 non_pci_non_serial");
            syscall.shutdown();
        }
    }

    if (!saw_any_device) {
        t.fail("§2.4.5 empty");
        syscall.shutdown();
    }

    t.pass("§2.4.5");
    syscall.shutdown();
}
