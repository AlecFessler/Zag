const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.10.10 — `proc_create` grants parent full `ProcessHandleRights` on the child handle.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits())));
    // Find the handle in perm_view and check rights.
    const full_rights: u16 = @bitCast(perms.ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .send_process = true,
        .send_device = true,
        .kill = true,
        .grant = true,
    });
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            if (view[i].rights == full_rights) {
                found = true;
            }
            break;
        }
    }
    if (found) {
        t.pass("§4.10.10");
    } else {
        t.fail("§4.10.10");
    }
    syscall.shutdown();
}
