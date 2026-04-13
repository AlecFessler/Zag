const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.92 — `pmu_start` on a target thread that is not the caller and not in `.faulted` or `.suspended` state returns `E_BUSY`.
///
/// The remote-target rule: `pmu_start` on a live running thread other
/// than the caller must return `E_BUSY` because stamping the target's
/// PMU state concurrently with its save/restore hooks would race.
/// Self-profiling is always permitted regardless of thread state.
var worker_ready: u64 align(8) = 0;
var worker_stop: u64 align(8) = 0;

fn workerLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_stop, .seq_cst) == 0) syscall.thread_yield();
}

pub fn main(_: u64) void {
    const pmu = t.requirePmu("§4.1.92");

    const h = syscall.thread_create(&workerLoop, 0, 4);
    if (h <= 0) {
        t.failWithVal("§4.1.92 thread_create", 1, h);
        syscall.shutdown();
    }
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    // Worker is running, not faulted or suspended — pmu_start on it
    // from the parent must return E_BUSY.
    var cfg = syscall.PmuCounterConfig{ .event = pmu.event, .has_threshold = false, .overflow_threshold = 0 };
    const rc = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);
    if (rc != syscall.E_BUSY) {
        t.failWithVal("§4.1.92", syscall.E_BUSY, rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    t.pass("§4.1.92");
    @atomicStore(u64, &worker_stop, 1, .seq_cst);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
