const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.31 — `fault_set_thread_mode` with mode `exclude_permanent` sets `exclude_permanent` and clears `exclude_oneshot`.
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

    // Acquire fault_handler for the child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Find the thread handle for the child.
    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
            thread_handle = view[i].handle;
            break;
        }
    }

    if (thread_handle == 0) {
        t.fail("§2.12.31 no thread handle found");
        syscall.shutdown();
    }

    // First set to exclude_next so we can verify exclude_permanent clears it.
    _ = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_NEXT);

    // Now set mode to exclude_permanent — should set exclude_permanent, clear exclude_oneshot.
    const rc = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);
    t.expectEqual("§2.12.31", 0, rc);
    syscall.shutdown();
}
