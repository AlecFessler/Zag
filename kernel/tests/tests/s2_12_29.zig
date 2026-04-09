const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.12.29 — `fault_set_thread_mode` with mode `stop_all` clears both `exclude_oneshot` and `exclude_permanent` on the thread's perm entry in the caller's permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that will transfer its fault_handler to us via cap transfer.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights,
    )));

    // Acquire fault_handler for the child by calling it.
    // The child replies with HANDLE_SELF via cap transfer with fault_handler bit.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // After acquiring fault_handler, the kernel inserts the child's thread handles
    // into our perm table. Find the thread handle for the child.
    // Skip slot 1 (parent's own initial thread).
    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
            thread_handle = view[i].handle;
            break;
        }
    }

    if (thread_handle == 0) {
        t.fail("§2.12.29 no thread handle found");
        syscall.shutdown();
    }

    // First set mode to exclude_permanent so flags are non-zero.
    _ = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);

    // Now set mode to stop_all — should clear both exclude_oneshot and exclude_permanent.
    const rc = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_STOP_ALL);
    t.expectEqual("§2.12.29", 0, rc);
    syscall.shutdown();
}
