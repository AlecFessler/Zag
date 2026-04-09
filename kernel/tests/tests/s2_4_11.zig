const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// §2.4.11 — `thread_suspend` on a `.faulted` thread returns `E_BUSY`
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that transfers fault_handler to us, then faults.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    // Acquire fault_handler via cap transfer; the child returns from reply
    // and immediately faults. The kernel routes the fault to our box per
    // §2.12.10 and the faulting thread enters `.faulted` state.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Block on fault_recv to make sure the fault has actually been delivered
    // (i.e., the thread is in `.faulted` and not still mid-fault).
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.fail("§2.4.11 fault_recv failed");
        syscall.shutdown();
    }

    // Find the child's thread handle in our perm_view.
    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_handle = view[i].handle;
            break;
        }
    }
    if (thread_handle == 0) {
        t.fail("§2.4.11 no thread handle found");
        syscall.shutdown();
    }

    // thread_suspend on a `.faulted` thread must return E_BUSY.
    const rc = syscall.thread_suspend(thread_handle);
    t.expectEqual("§2.4.11", E_BUSY, rc);
    syscall.shutdown();
}
