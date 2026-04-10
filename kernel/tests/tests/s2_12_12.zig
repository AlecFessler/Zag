const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const FAULT_REASON_BREAKPOINT: u8 = 14;

/// §2.12.12 — A `#BP` (int3) exception delivers a fault message with `fault_reason = breakpoint` (14) rather than killing the process immediately.
pub fn main(_: u64) void {
    // Spawn a child that cap-transfers fault_handler to us, then int3s.
    const child_rights = (perms.ProcessRights{
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_int3_after_transfer.ptr),
        children.child_int3_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§2.12.12 fault_recv", 0, token);
        syscall.shutdown();
    }

    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    if (fm.fault_reason == FAULT_REASON_BREAKPOINT) {
        t.pass("§2.12.12");
    } else {
        t.failWithVal("§2.12.12 fault_reason", FAULT_REASON_BREAKPOINT, @intCast(fm.fault_reason));
    }

    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
