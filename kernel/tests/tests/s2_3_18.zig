const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.18 — Sending `HANDLE_SELF` via capability transfer gives the recipient a process handle to the sender.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn child_send_self — it replies with its HANDLE_SELF via cap transfer.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self.ptr), children.child_send_self.len, child_rights.bits())));

    // Call the child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // We should now have a second process handle pointing to the same child.
    // Find it — it should be a process entry with a different handle ID than child_handle.
    var second_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and view[i].handle != child_handle)
        {
            second_handle = view[i].handle;
            break;
        }
    }
    // Verify the second handle exists (transferred HANDLE_SELF gave us a handle to the child).
    if (second_handle != 0) {
        t.pass("§2.3.18");
    } else {
        t.fail("§2.3.18");
    }
    syscall.shutdown();
}
