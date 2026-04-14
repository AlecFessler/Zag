const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

/// §4.1.59 — `fault_reply` returns `E_NOENT` if `fault_token` does not match the currently pending thread
pub fn main(_: u64) void {
    // Spawn child that transfers fault_handler then faults.
    const child_rights = perms.ProcessRights{
        .fault_handler = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.1.59 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(child_ret);

    // Acquire fault_handler.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the fault.
    var fault_msg: syscall.FaultMessage = undefined;
    const token_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (token_ret < 0) {
        t.failWithVal("§4.1.59 fault_recv", 0, token_ret);
        syscall.shutdown();
    }

    // Reply with a wrong token (the real token + 1).
    const wrong_token: u64 = @as(u64, @bitCast(token_ret)) +% 1;
    const reply_ret = syscall.fault_reply_simple(wrong_token, syscall.FAULT_KILL);
    t.expectEqual("§4.1.59", E_NOENT, reply_ret);

    syscall.shutdown();
}
