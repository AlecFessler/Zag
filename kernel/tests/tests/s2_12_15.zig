const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.15 — `fault_recv` with the blocking flag set blocks until a fault message is available in the calling process's fault box
/// is available in the calling process's fault box.
pub fn main(_: u64) void {
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
    // After reply, child will null-deref and fault.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // fault_recv with blocking=1 should block until the child's fault arrives.
    // If it returned successfully (positive token), it blocked and woke up when
    // the fault message became available.
    var fault_msg: syscall.FaultMessage = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_msg), 1);

    if (token > 0) {
        t.pass("§2.12.15");
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    } else {
        t.failWithVal("§2.12.15", 1, token);
    }

    syscall.shutdown();
}
