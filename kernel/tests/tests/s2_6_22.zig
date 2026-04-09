const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.22 — All threads are removed on restart; only a fresh initial thread runs.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // child_multithread_exit spawns 3 extra threads (4 total) on first boot,
    // waits for them to start, then all exit. After restart, only the initial
    // thread runs. The child enters ipc_recv on second boot and replies.
    const child_rights = (perms.ProcessRights{ .restart = true, .spawn_thread = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_multithread_exit.ptr),
        children.child_multithread_exit.len,
        child_rights,
    )));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Wait for restart.
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() == 0) {
        t.fail("§2.6.22");
        syscall.shutdown();
    }
    // Call the child — if it responds, only the initial thread is running post-restart.
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{}, &reply);
    if (rc == 0 and reply.words[0] > 0) {
        t.pass("§2.6.22");
    } else {
        t.fail("§2.6.22");
    }
    syscall.shutdown();
}
