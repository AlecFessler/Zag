const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.21 — A `.faulted` thread is not scheduled and does not appear on any run queue.
///
/// A .faulted thread is only observable via the fault delivery channel. We
/// prove the scheduling property behaviorally: once the faulting thread is
/// in `.faulted`, the kernel must re-enqueue it when fault_reply issues
/// FAULT_RESUME. If the thread had remained on the run queue, the resume
/// would be a no-op and the same instruction would execute only once; in
/// fact it must run again and re-fault at the same address.
pub fn main(_: u64) void {
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // First fault: the null-deref.
    var fault_buf1: [256]u8 align(8) = undefined;
    const token1 = syscall.fault_recv(@intFromPtr(&fault_buf1), 1);
    if (token1 < 0) {
        t.failWithVal("§2.4.21 fault_recv 1", 0, token1);
        syscall.shutdown();
    }
    const fm1: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf1));
    const addr1 = fm1.fault_addr;

    // Resume unchanged. The thread was .faulted and off the run queue; the
    // kernel must re-enqueue it. Once resumed it will execute the same
    // instruction again and re-fault at the same address.
    const rc = syscall.fault_reply_simple(@bitCast(token1), syscall.FAULT_RESUME);
    if (rc != 0) {
        t.failWithVal("§2.4.21 fault_reply RESUME", 0, rc);
        syscall.shutdown();
    }

    // Block on the second fault from the resumed thread.
    var fault_buf2: [256]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 1);
    if (token2 < 0) {
        t.failWithVal("§2.4.21 fault_recv 2", 0, token2);
        syscall.shutdown();
    }
    const fm2: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf2));
    if (fm2.fault_addr == addr1) {
        t.pass("§2.4.21");
    } else {
        t.fail("§2.4.21 second fault at different address");
    }
    _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);
    syscall.shutdown();
}
