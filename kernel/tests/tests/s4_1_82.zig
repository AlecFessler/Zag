const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.82 — `pmu_start` returns `E_OK` on success.
pub fn main(_: u64) void {
    const pmu = t.requirePmu("§4.1.82");
    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{ .event = pmu.event, .has_threshold = false, .overflow_threshold = 0 };
    const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
    if (rc != syscall.E_OK) {
        t.failWithVal("§4.1.82", syscall.E_OK, rc);
        syscall.shutdown();
    }
    _ = syscall.pmu_stop(self_thread);
    t.pass("§4.1.82");
    syscall.shutdown();
}
