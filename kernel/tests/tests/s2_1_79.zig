const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.79 — The user permissions view is kept in sync with the kernel permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child and acquire the fault_handler cap for it via cap transfer.
    // Per §2.12.4 the kernel inserts handles to the child's threads into our
    // permissions table; that insertion must be reflected in our user view.
    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Find the child's main thread handle now mirrored into our view.
    // Skip slot 1 which is our own initial thread.
    var child_thread_slot: usize = 128;
    var child_thread: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
            child_thread_slot = i;
            child_thread = view[i].handle;
            break;
        }
    }
    if (child_thread == 0) {
        t.fail("§2.1.79 child thread not mirrored into handler view");
        syscall.shutdown();
    }

    // Mutation of the target's table: kill the child's only thread. Per
    // §2.4.6 the kernel clears the thread from both the target's table and
    // the handler's table and calls syncUserView on both. Our (handler)
    // view must reflect that cross-table sync.
    const kill_rc = syscall.thread_kill(child_thread);
    if (kill_rc != 0) {
        t.failWithVal("§2.1.79 thread_kill", 0, kill_rc);
        syscall.shutdown();
    }

    var iters: u32 = 0;
    while (iters < 20000) : (iters += 1) {
        syscall.thread_yield();
        if (view[child_thread_slot].entry_type != perm_view.ENTRY_TYPE_THREAD or
            view[child_thread_slot].handle != child_thread)
        {
            t.pass("§2.1.79");
            syscall.shutdown();
        }
    }

    t.fail("§2.1.79 handler view did not reflect target table mutation");
    syscall.shutdown();
}
