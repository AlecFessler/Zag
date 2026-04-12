const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.3.28 — A restarting process is a valid IPC target.
/// Spawn restartable child_ipc_restart_server. It crashes on first boot (exits
/// without replying). After restart, it receives again and replies with word+100.
/// The caller's ipc_call blocks across the restart and gets the reply, proving
/// the restarted process is a valid IPC target.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn restartable child_ipc_restart_server
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_restart_server.ptr), children.child_ipc_restart_server.len, child_rights)));

    // ipc_call blocks. Child receives on first boot, exits without replying (crash).
    // On restart, child receives again (pending caller re-queued) and replies word+100.
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(ch, &.{0x42}, &reply);

    // Find child slot and verify it restarted
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }

    const restarted = view[slot].processRestartCount() > 0;
    const got_reply = rc == 0 and reply.words[0] == 0x42 + 100;

    if (restarted and got_reply) {
        t.pass("§3.3.28");
    } else {
        t.fail("§3.3.28");
    }
    syscall.shutdown();
}
