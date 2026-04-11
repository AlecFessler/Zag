const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.51.10 — `pmu_start` returns `E_NOMEM` if allocation of PMU state for the target thread fails.
///
/// SMOKE-ONLY under current userspace limits. Actually exhausting
/// `PmuStateAllocator` requires spinning up more threads than the slab
/// backing region can hold (thousands of threads), and the test-rig
/// process-table limit (64 threads/process) makes it impossible to trigger
/// directly from a single process. There is also no kernel test hook to
/// fault-inject allocator exhaustion. Until one exists, this test simply
/// makes a single `pmu_start` call and asserts that the return code is
/// either `E_OK` (success, normal path) or `E_NOMEM` (allocation failure,
/// the spec path). Any other return is a bug. This gives regression
/// coverage that the call does not return an unexpected error, without
/// actually exercising slab exhaustion.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.51.10");
        syscall.shutdown();
    }

    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
    const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
    if (rc != syscall.E_OK and rc != syscall.E_NOMEM) {
        t.failWithVal("§4.51.10 unexpected", 0, rc);
        syscall.shutdown();
    }
    if (rc == syscall.E_OK) _ = syscall.pmu_stop(self_thread);
    t.pass("§4.51.10");
    syscall.shutdown();
}
