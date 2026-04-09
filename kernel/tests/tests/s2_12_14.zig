const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.14 — `FaultMessage.thread_handle` is the handle ID of the faulting thread as it appears in the handler's own permissions table.
/// as it appears in the handler's own permissions table. This value is also the
/// fault token returned by fault_recv.
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
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Child will now null-deref and fault. Give it time.
    syscall.thread_yield();
    syscall.thread_yield();

    // Receive the fault message (blocking).
    var fault_msg: syscall.FaultMessage = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_msg), 1);

    if (token < 0) {
        t.fail("§2.12.14");
        syscall.shutdown();
    }

    // Per §2.12.4, when we acquired fault_handler, the kernel inserted thread handles
    // for the child's threads into our perm table. Find the thread handle.
    // Skip slot 1 — that's parent's own initial thread.
    var found_thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            found_thread_handle = view[i].handle;
            break;
        }
    }

    // FaultMessage.thread_handle should match the thread handle in our perm table,
    // and should also equal the fault token returned by fault_recv.
    const token_u64: u64 = @bitCast(token);
    if (fault_msg.thread_handle == found_thread_handle and
        fault_msg.thread_handle == token_u64 and
        found_thread_handle != 0)
    {
        t.pass("§2.12.14");
    } else {
        t.fail("§2.12.14");
    }

    // Clean up.
    _ = syscall.fault_reply_simple(token_u64, syscall.FAULT_KILL);
    syscall.shutdown();
}
