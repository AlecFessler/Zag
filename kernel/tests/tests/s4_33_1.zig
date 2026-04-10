const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.33.1 — `fault_recv` returns the fault token (positive u64, equal to the faulting thread's handle ID in the caller's perm table) on success and writes a `FaultMessage` to `buf_ptr`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{
        .fault_handler = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.33.1 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(child_ret);

    // Acquire fault_handler via cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);

    if (recv_ret < 0) {
        t.failWithVal("§4.33.1 fault_recv rc", 0, recv_ret);
        syscall.shutdown();
    }

    // Token must exactly equal the FaultMessage.thread_handle field.
    const token_u: u64 = @bitCast(recv_ret);
    if (token_u == fault_msg.thread_handle and token_u != 0) {
        t.pass("§4.33.1 token == FaultMessage.thread_handle");
    } else {
        t.fail("§4.33.1 token / thread_handle mismatch");
        syscall.shutdown();
    }

    // Sanity-check other FaultMessage fields.
    if (fault_msg.process_handle == 0) {
        t.fail("§4.33.1 process_handle is zero");
        syscall.shutdown();
    }
    // child_fault_after_transfer does a null read → invalid_read.
    if (fault_msg.fault_reason == 0) {
        t.fail("§4.33.1 fault_reason = none");
        syscall.shutdown();
    }
    t.pass("§4.33.1 FaultMessage populated");
    syscall.shutdown();
}
