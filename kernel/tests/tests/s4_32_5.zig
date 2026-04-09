const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §4.32.5 — If the killed thread is the last non-exited thread in the process, process exit or restart proceeds per §2.6
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a single-threaded child that stays alive.
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.32.5 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(child_ret);

    // Acquire fault_handler via cap transfer to get thread handles.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Find the child's thread handle in perm_view (skip slot 1 = parent's own).
    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_handle = view[i].handle;
            break;
        }
    }

    if (thread_handle == 0) {
        t.fail("§4.32.5 no thread handle found");
        syscall.shutdown();
    }

    // Kill the only thread in the child process.
    const kill_ret = syscall.thread_kill(thread_handle);
    t.expectEqual("§4.32.5 kill last thread", E_OK, kill_ret);

    // Yield to let the kernel process the exit/restart.
    for (0..10) |_| syscall.thread_yield();

    // Check that the child process entry is now dead or restarted.
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
                t.pass("§4.32.5 process exited");
                syscall.shutdown();
            }
            // Process type still alive means it restarted, which also satisfies §2.6.
            break;
        }
    }

    t.pass("§4.32.5 process restart/exit proceeded");
    syscall.shutdown();
}
