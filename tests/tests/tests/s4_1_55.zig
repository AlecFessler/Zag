const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// §4.1.55 — `fault_recv` returns `E_BUSY` if the fault box is already in `pending_reply` state
pub fn main(_: u64) void {
    // To get into pending_reply state:
    // 1. Spawn a child that faults
    // 2. fault_recv to get the fault (transitions to pending_reply)
    // 3. Call fault_recv again without replying -> E_BUSY

    const child_rights = perms.ProcessRights{
        .fault_handler = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.1.55 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(child_ret);

    // Acquire fault_handler.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the fault (enters pending_reply state).
    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§4.1.55 first fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    // Second fault_recv without replying should return E_BUSY.
    var fault_msg2: syscall.FaultMessage = undefined;
    const ret2 = syscall.fault_recv(@intFromPtr(&fault_msg2), 0);
    t.expectEqual("§4.1.55", E_BUSY, ret2);

    syscall.shutdown();
}
