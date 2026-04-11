const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.51.6 — `pmu_start` with `count` exceeding `PmuInfo.num_counters` returns `E_INVAL`.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK) {
        t.fail("§4.51.6 pmu_info");
        syscall.shutdown();
    }

    const self_thread: u64 = @bitCast(syscall.thread_self());
    // Use a supported event when available so this test exercises the
    // `count > num_counters` check rather than falling through a
    // supported-event check.
    const evt: syscall.PmuEvent = syscall.pickSupportedEvent(info) orelse .cycles;
    var cfgs: [syscall.PMU_MAX_COUNTERS + 1]syscall.PmuCounterConfig = undefined;
    for (&cfgs) |*c| c.* = .{ .event = evt, .has_threshold = false, .overflow_threshold = 0 };

    const excess: u64 = @as(u64, info.num_counters) + 1;
    const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfgs), excess);
    t.expectEqual("§4.51.6", syscall.E_INVAL, rc);
    syscall.shutdown();
}
