const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §5.1.5 — Root service holds `ProcessRights.set_time` at boot.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Slot 0 is the root service's own process entry
    const entry = &view[0];
    const rights: perms.ProcessRights = @bitCast(@as(u16, @truncate(entry.rights)));
    if (rights.set_time) {
        t.pass("§5.1.5");
    } else {
        t.fail("§5.1.5");
    }
    syscall.shutdown();
}
