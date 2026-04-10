const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.18 — `thread_kill` on the last non-exited thread in a process triggers process exit or restart per §2.6 semantics.
///
/// We spawn a non-restartable, single-threaded child whose fault_handler
/// relationship we acquire via cap transfer. Per §2.12.4 the kernel gives
/// us a handle to the child's only thread. We then thread_kill that handle
/// and observe the child's perm-view entry convert to `dead_process`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights,
    )));

    // Acquire fault_handler for the child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Find the child's main thread handle (inserted by §2.12.4). Skip
    // slot 1 which is our own initial thread.
    var child_thread: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
            child_thread = view[i].handle;
            break;
        }
    }
    if (child_thread == 0) {
        t.fail("§2.4.18 no child thread handle");
        syscall.shutdown();
    }

    // Kill the child's only thread. Per §2.4.18 this must trigger process
    // death (the child has no restart context).
    const rc = syscall.thread_kill(child_thread);
    if (rc != 0) {
        t.failWithVal("§2.4.18 thread_kill", 0, rc);
        syscall.shutdown();
    }

    // Wait for the child's entry to flip to dead_process.
    var iters: u32 = 0;
    while (iters < 2000) : (iters += 1) {
        syscall.thread_yield();
        for (0..128) |i| {
            if (view[i].handle == child_handle and
                view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS)
            {
                t.pass("§2.4.18");
                syscall.shutdown();
            }
        }
    }
    t.fail("§2.4.18 child never became dead_process");
    syscall.shutdown();
}
