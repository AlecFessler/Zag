const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const TOKEN: u64 = 0x5E1F_CA11_DEAD_BEEF;

/// §2.3.18 — Sending `HANDLE_SELF` via capability transfer gives the recipient a process handle to the sender.
/// recipient a process handle to the sender.
///
/// We don't just verify a new process slot appears — we actually USE it.
/// After the child replies with HANDLE_SELF via cap transfer, we find the
/// new handle in our perm view, then ipc_call back through it and expect
/// the child to reply with a distinguishing token. Proves the transferred
/// handle genuinely addresses the sender.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_then_reply_token.ptr),
        children.child_send_self_then_reply_token.len,
        child_rights.bits(),
    )));

    // Trigger the child's first reply_cap path.
    var reply1: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply1);

    // Discover the new process handle — a process entry that isn't the
    // original child_handle and isn't slot 0.
    var new_handle: u64 = 0;
    for (0..128) |i| {
        if (i == 0) continue;
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != child_handle and
            view[i].handle != 0)
        {
            new_handle = view[i].handle;
            break;
        }
    }
    if (new_handle == 0) {
        t.fail("§2.3.18");
        syscall.shutdown();
    }

    // Use the transferred handle for a second call; child should reply TOKEN.
    var reply2: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(new_handle, &.{}, &reply2);

    if (rc == 0 and reply2.words[0] == TOKEN) {
        t.pass("§2.3.18");
    } else {
        t.fail("§2.3.18");
    }
    syscall.shutdown();
}
