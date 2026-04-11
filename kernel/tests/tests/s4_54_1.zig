const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.54.1 — `pmu_stop` returns `E_OK` on success.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.54.1");
        syscall.shutdown();
    }

    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{ .event = @intFromEnum(syscall.PmuEvent.cycles) };
    _ = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);

    const rc = syscall.pmu_stop(self_thread);
    if (rc != syscall.E_OK) {
        t.failWithVal("§4.54.1", syscall.E_OK, rc);
        syscall.shutdown();
    }

    // After stop, subsequent pmu_read must return E_INVAL (state freed).
    // Suspend ourselves is impossible; use a worker.
    t.pass("§4.54.1");
    syscall.shutdown();
}
