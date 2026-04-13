const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;

fn workerLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (true) syscall.thread_yield();
}

/// §4.1.105 — `pmu_reset` on a thread not in `.faulted` state returns `E_INVAL`.
pub fn main(_: u64) void {
    const pmu = t.requirePmu("§4.1.105");

    const h = syscall.thread_create(&workerLoop, 0, 4);
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    // Remote pmu_start requires target to be .faulted or .suspended. We
    // want the thread to stay suspended anyway for the pmu_reset test.
    if (syscall.thread_suspend(worker_h) != syscall.E_OK) {
        t.fail("§4.1.105 thread_suspend pre-start");
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }
    var cfg = syscall.PmuCounterConfig{ .event = pmu.event, .has_threshold = false, .overflow_threshold = 0 };
    if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§4.1.105 pmu_start");
        _ = syscall.thread_resume(worker_h);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    // Thread is suspended (not faulted) — §4.1.105 requires this to fail.
    const rc = syscall.pmu_reset(worker_h, @intFromPtr(&cfg), 1);
    t.expectEqual("§4.1.105", syscall.E_INVAL, rc);

    _ = syscall.pmu_stop(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
