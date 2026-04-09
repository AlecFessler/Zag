const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.3 — Restart is triggered when a process with a restart context terminates by parent-initiated kill.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn restartable child_send_self.
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .restart = true }).bits();
    const h_parent: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self.ptr),
        children.child_send_self.len,
        child_rights,
    )));

    // Call child — it replies with HANDLE_SELF via cap transfer.
    // Now we have h_parent (from proc_create) and a second handle (from cap transfer).
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(h_parent, &.{}, &reply);

    // Find the cap-transferred handle (different from h_parent, process type).
    var h_child: u64 = 0;
    var h_child_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle != 0 and view[i].handle != h_parent and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            h_child = view[i].handle;
            h_child_slot = i;
            break;
        }
    }
    if (h_child == 0) {
        t.fail("§2.6.3");
        syscall.shutdown();
    }

    const rc_before = view[h_child_slot].processRestartCount();

    // Kill child via revoke of parent handle.
    // Child is restartable, so kill() triggers performRestart.
    _ = syscall.revoke_perm(h_parent);

    // Wait for restart_count to increment.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[h_child_slot].processRestartCount() > rc_before) break;
        syscall.thread_yield();
    }

    if (view[h_child_slot].processRestartCount() > rc_before) {
        t.pass("§2.6.3");
    } else {
        t.fail("§2.6.3");
    }
    syscall.shutdown();
}
