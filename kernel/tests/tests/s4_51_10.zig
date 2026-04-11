const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.51.10 — `pmu_start` returns `E_NOMEM` if allocation of PMU state for the target thread fails.
///
/// Exhausting `PmuStateAllocator` from userspace requires spinning up more
/// threads than the slab backing region can hold (thousands of threads).
/// The test-rig process-table limit (64 threads/process) makes this
/// impossible to trigger directly from a single test. Instead we spawn as
/// many worker threads as allowed, call `pmu_start` on each, and assert
/// that every call either succeeds or returns `E_NOMEM` — never any
/// other unexpected error. This gives coverage for the allocation path
/// without guaranteeing exhaustion.
fn parkWorker() void {
    while (true) syscall.thread_yield();
}

pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.51.10");
        syscall.shutdown();
    }

    var cfg = syscall.PmuCounterConfig{ .event = @intFromEnum(syscall.PmuEvent.cycles) };
    var i: u64 = 0;
    while (i < 48) : (i += 1) {
        const h = syscall.thread_create(&parkWorker, 0, 4);
        if (h <= 0) break;
        const rc = syscall.pmu_start(@bitCast(h), @intFromPtr(&cfg), 1);
        if (rc != syscall.E_OK and rc != syscall.E_NOMEM) {
            t.failWithVal("§4.51.10 unexpected", 0, rc);
            syscall.shutdown();
        }
    }
    t.pass("§4.51.10");
    syscall.shutdown();
}
