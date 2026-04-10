const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

fn worker() void {
    while (true) {
        syscall.thread_yield();
    }
}

/// §2.3.19 — Thread handles are not transferable via message passing.
pub fn main(_: u64) void {
    // Create a second thread so we have a thread handle to attempt transferring.
    const handle_ret = syscall.thread_create(&worker, 0, 4);
    if (handle_ret <= 0) {
        t.failWithVal("§2.3.19 thread_create", 1, handle_ret);
        syscall.shutdown();
    }
    const thread_handle: u64 = @bitCast(handle_ret);

    // Spawn a child process to act as the IPC target.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_ipc_server.ptr),
        children.child_ipc_server.len,
        child_rights.bits(),
    )));

    // Let child start and block on recv.
    for (0..5) |_| syscall.thread_yield();

    // Attempt to transfer the thread handle via cap transfer — should fail.
    // Cap transfer sends word[0] = handle, word[1] = rights.
    const thread_rights: u64 = perms.ThreadHandleRights.full.bits();
    var reply: syscall.IpcMessage = .{};
    const ret = syscall.ipc_call_cap(child_handle, &.{ thread_handle, thread_rights }, &reply);

    // Kernel rejects thread-handle cap transfer in validateIpcSendRights via
    // the `else` branch — the cap object is neither SHM nor process nor
    // device_region, so E_INVAL is returned.
    if (ret == E_INVAL) {
        t.pass("§2.3.19");
    } else {
        t.failWithVal("§2.3.19", E_INVAL, ret);
    }
    syscall.shutdown();
}
