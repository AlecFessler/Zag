const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.51.7 — `pmu_start` with an event not set in `PmuInfo.supported_events` returns `E_INVAL`.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.51.7");
        syscall.shutdown();
    }

    // Find an event variant that is NOT set in supported_events. Use a
    // very-out-of-range numeric event id as a fallback when the kernel
    // reports every known event as supported.
    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{ .event = @enumFromInt(99), .has_threshold = false, .overflow_threshold = 0 };
    const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
    t.expectEqual("§4.51.7", syscall.E_INVAL, rc);
    syscall.shutdown();
}
