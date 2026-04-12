const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.16 — The badge bit is stored in the `badge_byte` field (offset 9, the byte after `entry_type`) of the device entry in the user permissions view.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region entry and verify badge_byte holds a valid badge (0-63).
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const badge: u64 = e.badge_byte;
        if (badge < 64) {
            t.pass("§2.5.16");
            syscall.shutdown();
        }
    }
    t.fail("§2.5.16");
    syscall.shutdown();
}
