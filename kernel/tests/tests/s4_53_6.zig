const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.53.6 — `pmu_reset` on a thread with no PMU state returns `E_INVAL`.
pub fn main(_: u64) void {
    // Spawn a child that cap-transfers fault_handler and then int3s.
    // The child never calls pmu_start, so its thread has no PMU state.
    const child_rights = perms.ProcessRights{ .fault_handler = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_int3_after_transfer.ptr),
        children.child_int3_after_transfer.len,
        child_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§4.53.6 fault_recv", 0, token);
        syscall.shutdown();
    }
    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    const target = fm.thread_handle;

    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
    const rc = syscall.pmu_reset(target, @intFromPtr(&cfg), 1);
    t.expectEqual("§4.53.6", syscall.E_INVAL, rc);

    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
