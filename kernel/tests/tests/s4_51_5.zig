const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.51.5 — `pmu_start` with `count == 0` returns `E_INVAL`.
pub fn main(_: u64) void {
    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{ .event = @intFromEnum(syscall.PmuEvent.cycles) };
    const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 0);
    t.expectEqual("§4.51.5", syscall.E_INVAL, rc);
    syscall.shutdown();
}
