const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.11.27 — Process capability transfer inserts with `ProcessHandleRights` encoding.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Use child_send_self: recv → reply_cap with HANDLE_SELF
    // Parent gets a process handle to the child with ProcessHandleRights encoding
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self.ptr), children.child_send_self.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    // Find the transferred process handle (different from ch) and verify its rights
    // match the ProcessHandleRights encoding sent by child_send_self.
    const expected_rights: u16 = @truncate((perms.ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .send_process = true,
        .send_device = true,
        .kill = true,
        .grant = true,
    }).bits());
    var found = false;
    for (0..128) |i| {
        if (view[i].handle != 0 and view[i].handle != ch and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            if (view[i].rights == expected_rights) {
                found = true;
            }
            break;
        }
    }
    if (found) {
        t.pass("§2.11.27");
    } else {
        t.fail("§2.11.27");
    }
    syscall.shutdown();
}
