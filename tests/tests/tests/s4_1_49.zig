const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.49 — On a PMU overflow fault, a profiler typically calls `pmu_read` to retrieve the final counter values, `pmu_reset` to reconfigure counters with the next threshold, and `fault_reply` with `FAULT_RESUME` to resume the thread.
pub fn main(_: u64) void {
    const pmu = t.requirePmuOverflow("§4.1.49");
    const evt = pmu.event;

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
        t.failWithVal("§4.1.49 fault_recv", 0, token);
        syscall.shutdown();
    }
    const token_u: u64 = @bitCast(token);
    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    const target_thread = fm.thread_handle;

    // Step 1: pmu_read on the faulted thread.
    var sample: syscall.PmuSample = undefined;
    const read_rc = syscall.pmu_read(target_thread, @intFromPtr(&sample));
    if (read_rc != syscall.E_OK) {
        t.failWithVal("§4.1.49 pmu_read", syscall.E_OK, read_rc);
        _ = syscall.fault_reply_simple(token_u, syscall.FAULT_KILL);
        syscall.shutdown();
    }

    // Step 2: pmu_reset with a new threshold using a supported event.
    var cfg = syscall.PmuCounterConfig{
        .event = evt,
        .has_threshold = true,
        .overflow_threshold = 2048,
    };
    const reset_rc = syscall.pmu_reset(target_thread, @intFromPtr(&cfg), 1);
    if (reset_rc != syscall.E_OK) {
        t.failWithVal("§4.1.49 pmu_reset", syscall.E_OK, reset_rc);
        _ = syscall.fault_reply_simple(token_u, syscall.FAULT_KILL);
        syscall.shutdown();
    }

    // Step 3: fault_reply FAULT_RESUME — thread should be driven back
    // into running, re-fault on the new threshold, and deliver another
    // pmu_overflow fault.
    const reply_rc = syscall.fault_reply_simple(token_u, syscall.FAULT_RESUME);
    if (reply_rc != syscall.E_OK) {
        t.failWithVal("§4.1.49 fault_reply", syscall.E_OK, reply_rc);
        syscall.shutdown();
    }

    var fault_buf2: [256]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 1);
    if (token2 < 0) {
        t.failWithVal("§4.1.49 fault_recv 2", 0, token2);
        syscall.shutdown();
    }
    const fm2: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf2));
    if (fm2.fault_reason != syscall.FAULT_REASON_PMU_OVERFLOW) {
        t.failWithVal("§4.1.49 fault_reason 2", syscall.FAULT_REASON_PMU_OVERFLOW, @intCast(fm2.fault_reason));
        _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    t.pass("§4.1.49");
    _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);
    syscall.shutdown();
}
