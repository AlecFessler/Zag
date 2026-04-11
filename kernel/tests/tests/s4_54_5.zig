const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.54.5 — `pmu_stop` on a thread with no PMU state (never started, or already stopped) returns `E_INVAL`.
pub fn main(_: u64) void {
    // Case 1: thread_self has never called pmu_start.
    const self_thread: u64 = @bitCast(syscall.thread_self());
    const rc_never = syscall.pmu_stop(self_thread);
    if (rc_never != syscall.E_INVAL) {
        t.failWithVal("§4.54.5 never-started", syscall.E_INVAL, rc_never);
        syscall.shutdown();
    }

    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.54.5");
        syscall.shutdown();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        t.pass("§4.54.5");
        syscall.shutdown();
    };

    // Case 2: start then stop then stop again.
    var cfg = syscall.PmuCounterConfig{ .event = evt, .has_threshold = false, .overflow_threshold = 0 };
    _ = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
    _ = syscall.pmu_stop(self_thread);
    const rc_twice = syscall.pmu_stop(self_thread);
    if (rc_twice != syscall.E_INVAL) {
        t.failWithVal("§4.54.5 already-stopped", syscall.E_INVAL, rc_twice);
        syscall.shutdown();
    }

    t.pass("§4.54.5");
    syscall.shutdown();
}
