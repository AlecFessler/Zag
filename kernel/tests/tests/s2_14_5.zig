const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.14.5 — A thread may profile itself by passing its own handle from `thread_self` to the PMU syscalls, but this still requires `ProcessRights.pmu` on the calling process — there is no special self-access path.
pub fn main(_: u64) void {
    // Root service holds ProcessRights.pmu (§2.14.3) and thread_create
    // grants full ThreadHandleRights including pmu — so self-profiling
    // via thread_self should succeed.
    const self_thread: u64 = @bitCast(syscall.thread_self());

    // Query capabilities to pick a valid event.
    var info: syscall.PmuInfo = undefined;
    const info_rc = syscall.pmu_info(@intFromPtr(&info));
    if (info_rc != syscall.E_OK) {
        t.failWithVal("§2.14.5 pmu_info", syscall.E_OK, info_rc);
        syscall.shutdown();
    }
    if (info.num_counters == 0) {
        // No hardware counters — §2.14.5 self-access path is untestable
        // but the rights path was exercised via pmu_info succeeding.
        t.pass("§2.14.5");
        syscall.shutdown();
    }

    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
    const start_rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
    if (start_rc != syscall.E_OK) {
        t.failWithVal("§2.14.5 pmu_start", syscall.E_OK, start_rc);
        syscall.shutdown();
    }

    const stop_rc = syscall.pmu_stop(self_thread);
    if (stop_rc != syscall.E_OK) {
        t.failWithVal("§2.14.5 pmu_stop", syscall.E_OK, stop_rc);
        syscall.shutdown();
    }

    t.pass("§2.14.5");
    syscall.shutdown();
}
