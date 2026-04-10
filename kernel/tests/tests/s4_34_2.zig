const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

const FAULT_EXCLUDE_NEXT: u64 = 0x1;
const FAULT_EXCLUDE_PERMANENT: u64 = 0x2;

/// §4.34.2 — `fault_reply` returns `E_INVAL` if the fault box is not in `pending_reply` state, if `action` is not a valid value (0, 1, or 2), or if both `FAULT_EXCLUDE_NEXT` and `FAULT_EXCLUDE_PERMANENT` flags are set simultaneously.
pub fn main(_: u64) void {
    // --- Branch (a): no pending fault. ---
    const ret_a = syscall.fault_reply_simple(0, syscall.FAULT_KILL);
    t.expectEqual("§4.34.2 no pending", E_INVAL, ret_a);

    // --- Receive a real fault so the box is in pending_reply for (b)/(c). ---
    const child_rights = perms.ProcessRights{ .fault_handler = true };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.34.2 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    var ipc_reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@bitCast(child_ret), &.{}, &ipc_reply);

    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§4.34.2 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }
    const token: u64 = @bitCast(recv_ret);

    // --- Branch (b): invalid action (5 > FAULT_RESUME_MODIFIED). ---
    const ret_b = syscall.fault_reply_simple(token, 5);
    t.expectEqual("§4.34.2 invalid action", E_INVAL, ret_b);

    // --- Branch (c): both exclude flags set. ---
    const ret_c = syscall.fault_reply_flags(
        token,
        syscall.FAULT_KILL,
        0,
        FAULT_EXCLUDE_NEXT | FAULT_EXCLUDE_PERMANENT,
    );
    t.expectEqual("§4.34.2 both exclude flags", E_INVAL, ret_c);

    syscall.shutdown();
}
