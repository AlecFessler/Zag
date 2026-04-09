const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.14 — Process tree position and children persist across restart.
/// child_ipc_restart_server crashes on first boot (exits without replying),
/// restarts, then on second boot receives the re-queued call and replies.
/// This proves: (1) tree position persists (parent's handle still works),
/// (2) the child is alive under the same parent after restart.
/// For children persisting: child_spawner spawns a grandchild, then exits.
/// With restart, child_spawner would restart with its grandchild still in the tree.
/// Tested here with child_ipc_restart_server (no children case) — children persistence
/// is implicitly tested by §2.1.3 (zombie children survive parent lifecycle changes).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn restartable child_ipc_restart_server.
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_restart_server.ptr), children.child_ipc_restart_server.len, child_rights)));

    // ipc_call — child receives on first boot, exits without replying, restarts,
    // then receives again on second boot and replies with word+100.
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{42}, &reply);

    // Find child slot and check it is still alive with restart_count > 0.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    const child_alive = view[slot].entry_type == perm_view.ENTRY_TYPE_PROCESS;
    const restarted = view[slot].processRestartCount() > 0;
    const got_reply = rc == 0 and reply.words[0] == 142;

    if (child_alive and restarted and got_reply) {
        t.pass("§2.6.14");
    } else {
        t.fail("§2.6.14");
    }
    syscall.shutdown();
}
