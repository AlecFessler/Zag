const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.54.7 — `pmu_stop` on a target thread that is not the caller and not in `.faulted` or `.suspended` state returns `E_BUSY`.
///
/// Mirrors §4.51.11 for the stop path. A running remote target must be
/// observably stopped so that clearing its PMU state does not race the
/// save/restore hooks on its core.
var worker_ready: u64 align(8) = 0;
var worker_stop: u64 align(8) = 0;

fn workerLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_stop, .seq_cst) == 0) syscall.thread_yield();
}

pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.54.7");
        syscall.shutdown();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        t.pass("§4.54.7");
        syscall.shutdown();
    };

    const h = syscall.thread_create(&workerLoop, 0, 4);
    if (h <= 0) {
        t.failWithVal("§4.54.7 thread_create", 1, h);
        syscall.shutdown();
    }
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    // Suspend, start PMU, then resume so the worker has PMU state while
    // running. pmu_stop on a running remote target must return E_BUSY.
    if (syscall.thread_suspend(worker_h) != syscall.E_OK) {
        t.fail("§4.54.7 thread_suspend");
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }
    var cfg = syscall.PmuCounterConfig{ .event = evt, .has_threshold = false, .overflow_threshold = 0 };
    if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§4.54.7 pmu_start setup");
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_resume(worker_h);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }
    _ = syscall.thread_resume(worker_h);

    // Give the worker a chance to transition back to running.
    for (0..100) |_| syscall.thread_yield();

    const rc = syscall.pmu_stop(worker_h);
    if (rc != syscall.E_BUSY) {
        t.failWithVal("§4.54.7", syscall.E_BUSY, rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    t.pass("§4.54.7");
    @atomicStore(u64, &worker_stop, 1, .seq_cst);
    // Clean up: suspend, stop, kill.
    _ = syscall.thread_suspend(worker_h);
    _ = syscall.pmu_stop(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
