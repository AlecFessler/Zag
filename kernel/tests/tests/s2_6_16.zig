const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.16 — Pending callers (received but not yet replied to) persist across restart.
/// child_ipc_restart_server: on first boot, receives a message but exits without
/// replying (pending caller re-queued). After restart, it receives again and
/// replies with word+100. If the caller gets the reply, the pending caller
/// persisted across the restart.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn restartable child_ipc_restart_server.
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_restart_server.ptr), children.child_ipc_restart_server.len, child_rights)));

    // ipc_call blocks. Child receives on first boot, exits without replying.
    // On restart, child receives again (pending caller re-queued) and replies.
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{50}, &reply);

    // Find child slot.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    const restarted = view[slot].processRestartCount() > 0;
    const got_reply = rc == 0 and reply.words[0] == 150;

    if (restarted and got_reply) {
        t.pass("§2.6.16");
    } else {
        t.fail("§2.6.16");
    }
    syscall.shutdown();
}
