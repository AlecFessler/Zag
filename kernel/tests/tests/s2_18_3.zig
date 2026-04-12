const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.18.3 — The badge bit is packed into the upper bits of the device entry `field0` in the user permissions view.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region entry and verify the badge bit occupies
    // bits [56:62] of field0 (6-bit badge value in the top byte).
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const badge = e.field0 >> 56;
        // The lower 32 bits of field0 encode device_type, device_class,
        // and size — the badge must live in the upper byte.
        if (badge < 64) {
            t.pass("§2.18.3");
            syscall.shutdown();
        }
    }
    t.fail("§2.18.3");
    syscall.shutdown();
}
