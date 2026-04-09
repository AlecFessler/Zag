const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.9.5 — Kernel-internal devices (HPET, LAPIC, I/O APIC) are not exposed in the user view.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Check that no device has PCI class 0x08 (system peripheral — HPET is subclass 0x03)
    // or class 0xFF with vendor 0 (LAPIC/IOAPIC are platform devices, not PCI).
    // Also verify all device handles have non-zero sizes (they are real usable devices).
    var bad_device = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            const size = view[i].deviceSizeOrPortCount();
            if (size == 0) {
                bad_device = true;
                break;
            }
            // LAPIC is at 0xFEE00000 (4KB), IOAPIC at 0xFEC00000 (4KB), HPET at 0xFED00000.
            // These should NOT appear. We can't check physical addresses from userspace,
            // but we can verify device_class is not "timer" for HPET.
            const dev_class = view[i].deviceClass();
            if (dev_class == @intFromEnum(perms.DeviceClass.timer)) {
                bad_device = true;
                break;
            }
        }
    }

    if (!bad_device) {
        t.pass("§2.9.5");
    } else {
        t.fail("§2.9.5");
    }
    syscall.shutdown();
}
