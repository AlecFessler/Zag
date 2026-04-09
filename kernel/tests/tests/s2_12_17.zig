const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// §2.12.17 — `fault_recv` returns `E_BUSY` if the fault box is already in `pending_reply` state
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
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Child will now null-deref and fault. Give it time.
    syscall.thread_yield();
    syscall.thread_yield();

    // First fault_recv — puts fault box into pending_reply state.
    var fault_msg: syscall.FaultMessage = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_msg), 1);

    if (token < 0) {
        t.fail("§2.12.17");
        syscall.shutdown();
    }

    // Second fault_recv — fault box is in pending_reply, should return E_BUSY.
    var fault_msg2: syscall.FaultMessage = undefined;
    const rc = syscall.fault_recv(@intFromPtr(&fault_msg2), 0);

    t.expectEqual("§2.12.17", E_BUSY, rc);

    // Clean up.
    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
