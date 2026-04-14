const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADADDR: i64 = -7;

/// §4.1.60 — `fault_reply` with `FAULT_RESUME_MODIFIED` and an unreadable or insufficiently sized `modified_regs_ptr` returns `E_BADADDR`
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
        t.failWithVal("§4.1.60 proc_create", 1, child_ret);
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
        t.failWithVal("§4.1.60 fault_recv", 0, token_ret);
        syscall.shutdown();
    }
    const token: u64 = @bitCast(token_ret);

    // Reply with FAULT_RESUME_MODIFIED but pass an unmapped pointer for modified_regs_ptr.
    const reply_ret = syscall.fault_reply_action(token, syscall.FAULT_RESUME_MODIFIED, 0xDEAD);
    t.expectEqual("§4.1.60", E_BADADDR, reply_ret);

    syscall.shutdown();
}
