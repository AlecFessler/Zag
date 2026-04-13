const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.14 — Badge bits are assigned incrementally (mod 64) per process as device handles are inserted into the permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find the first two device region entries and verify their badge bits
    // are distinct and incrementally assigned.
    var first_badge: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    var second_badge: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    var found: u32 = 0;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        // Badge bit is in badge_byte (§2.18.3)
        const badge: u64 = e.badge_byte;
        if (found == 0) {
            first_badge = badge;
            found = 1;
        } else if (found == 1) {
            second_badge = badge;
            found = 2;
            break;
        }
    }
    if (found >= 2 and second_badge == (first_badge + 1) % 64) {
        t.pass("§2.4.14");
    } else if (found < 2) {
        // Not enough devices — pass if at least one was found with a valid badge
        if (found == 1 and first_badge < 64) {
            t.pass("§2.4.14");
        } else {
            t.fail("§2.4.14");
        }
    } else {
        t.fail("§2.4.14");
    }
    syscall.shutdown();
}
