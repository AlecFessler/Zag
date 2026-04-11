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
    var cfgs: [syscall.PMU_MAX_COUNTERS + 1]syscall.PmuCounterConfig = undefined;
    for (&cfgs) |*c| c.* = .{ .event = @intFromEnum(syscall.PmuEvent.cycles) };

    const excess: u64 = @as(u64, info.num_counters) + 1;
    const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfgs), excess);
    t.expectEqual("§4.51.6", syscall.E_INVAL, rc);
    syscall.shutdown();
}
