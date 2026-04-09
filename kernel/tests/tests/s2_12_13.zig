const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.13 — `FaultMessage.process_handle` is the handle ID of the source process as it appears in the handler's own permissions table
/// as it appears in the handler's own permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child with fault_handler so it can transfer it to us.
    const child_rights = perms.ProcessRights{ .fault_handler = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    )));

    // Let child start and block on recv.
    syscall.thread_yield();
    syscall.thread_yield();

    // Call child to trigger cap transfer of HANDLE_SELF with fault_handler.
    // After this, we become the child's fault handler.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Child will now null-deref and fault. Give it time.
    syscall.thread_yield();
    syscall.thread_yield();

    // Receive the fault message (blocking).
    var fault_msg: syscall.FaultMessage = undefined;
    const rc = syscall.fault_recv(@intFromPtr(&fault_msg), 1);

    if (rc < 0) {
        t.fail("§2.12.13");
        syscall.shutdown();
    }

    // Find the child's process handle in our perm view.
    // The child_handle returned by proc_create is in our table; after cap transfer
    // the fault_handler bit was added to that existing entry per §2.12.3.
    // FaultMessage.process_handle should match that handle ID.
    var found_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            found_handle = view[i].handle;
            break;
        }
    }

    if (fault_msg.process_handle == found_handle and found_handle != 0) {
        t.pass("§2.12.13");
    } else {
        t.fail("§2.12.13");
    }

    // Clean up: reply to kill the faulted child.
    _ = syscall.fault_reply_simple(@bitCast(rc), syscall.FAULT_KILL);
    syscall.shutdown();
}
