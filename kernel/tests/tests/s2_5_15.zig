const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.15 — The badge bit is stored on the `PermissionEntry` for device region entries and exposed in the user permissions view so userspace can map notification bits to device handles without a syscall.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region entry and verify the badge_byte field is present
    // (i.e., badge_byte contains a valid badge < 64, per §2.18.3).
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const badge: u64 = e.badge_byte;
        if (badge < 64) {
            t.pass("§2.5.15");
            syscall.shutdown();
        }
    }
    // No device entries found — this means the test rig has no devices,
    // which should not happen under QEMU q35.
    t.fail("§2.5.15");
    syscall.shutdown();
}
