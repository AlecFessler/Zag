const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.48 — When a counter configured with an overflow threshold reaches that threshold the hardware raises a PMU interrupt.
pub fn main(_: u64) void {
    _ = t.requirePmuOverflow("§4.1.48");

    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
        .pmu = true,
    };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_pmu_overflow.ptr),
        children.child_pmu_overflow.len,
        child_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§4.1.48 fault_recv", 0, token);
        syscall.shutdown();
    }

    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    if (fm.fault_reason != syscall.FAULT_REASON_PMU_OVERFLOW) {
        t.failWithVal("§4.1.48 fault_reason",
            syscall.FAULT_REASON_PMU_OVERFLOW, @intCast(fm.fault_reason));
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }
    if (fm.rip == 0) {
        t.fail("§4.1.48 rip is zero");
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    t.pass("§4.1.48");
    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
