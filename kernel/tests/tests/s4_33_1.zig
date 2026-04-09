const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.33.1 — `fault_recv` returns the fault token (positive u64, equal to the faulting thread's handle ID in the caller's perm table) on success and writes a `FaultMessage` to `buf_ptr`
pub fn main(_: u64) void {
    // Spawn a child that transfers HANDLE_SELF with fault_handler, then faults.
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

    // Child will now fault. Receive the fault (blocking).
    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);

    // On success, recv_ret should be the fault token (>= 0).
    if (recv_ret >= 0) {
        t.pass("§4.33.1 fault_recv returns token");
    } else {
        t.failWithVal("§4.33.1 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    // Verify FaultMessage fields are populated.
    if (fault_msg.thread_handle != 0) {
        t.pass("§4.33.1 FaultMessage has thread_handle");
    } else {
        t.fail("§4.33.1 FaultMessage thread_handle is zero");
    }

    syscall.shutdown();
}
