const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.19.1 — `ProcessRights.power` gates both `sys_power` and `sys_cpu_power`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Slot 0 is the root service's own process entry — verify it has `power`.
    const entry = &view[0];
    const rights: perms.ProcessRights = @bitCast(@as(u16, @truncate(entry.rights)));
    if (rights.power) {
        t.pass("§2.19.1");
    } else {
        t.fail("§2.19.1");
    }
    syscall.shutdown();
}
