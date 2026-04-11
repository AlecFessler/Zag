const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.51.1 — `pmu_start` returns `E_OK` on success.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.51.1");
        syscall.shutdown();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        t.pass("§4.51.1");
        syscall.shutdown();
    };

    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{ .event = evt, .has_threshold = false, .overflow_threshold = 0 };
    const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
    if (rc != syscall.E_OK) {
        t.failWithVal("§4.51.1", syscall.E_OK, rc);
        syscall.shutdown();
    }
    _ = syscall.pmu_stop(self_thread);
    t.pass("§4.51.1");
    syscall.shutdown();
}
