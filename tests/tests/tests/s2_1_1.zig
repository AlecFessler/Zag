const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.1 — Spawning a child via `proc_create` establishes a parent/children link (process tree).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits())));
    // Check that the child appears in the parent's perm_view as a process entry.
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            found = true;
            break;
        }
    }
    if (found) {
        t.pass("§2.1.1");
    } else {
        t.fail("§2.1.1");
    }
    syscall.shutdown();
}
