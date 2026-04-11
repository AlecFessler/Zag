const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.53.7 — `pmu_reset` with invalid configuration (same rules as `pmu_start`: bad `count`, unsupported event, overflow unsupported) returns `E_INVAL`.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or
        info.num_counters == 0 or !info.overflow_support)
    {
        t.pass("§4.53.7");
        syscall.shutdown();
    }

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
        t.failWithVal("§4.53.7 fault_recv", 0, token);
        syscall.shutdown();
    }
    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    const target = fm.thread_handle;

    // count == 0 is invalid (mirrors §4.51.5).
    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
    const rc_zero = syscall.pmu_reset(target, @intFromPtr(&cfg), 0);
    if (rc_zero != syscall.E_INVAL) {
        t.failWithVal("§4.53.7 count=0", syscall.E_INVAL, rc_zero);
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    // Unsupported event (mirrors §4.51.7).
    var cfg_bad = syscall.PmuCounterConfig{ .event = @enumFromInt(99), .has_threshold = false, .overflow_threshold = 0 };
    const rc_event = syscall.pmu_reset(target, @intFromPtr(&cfg_bad), 1);
    if (rc_event != syscall.E_INVAL) {
        t.failWithVal("§4.53.7 bad event", syscall.E_INVAL, rc_event);
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    t.pass("§4.53.7");
    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
