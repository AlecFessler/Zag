const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_stop: u64 align(8) = 0;

fn spinLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_stop, .seq_cst) == 0) syscall.thread_yield();
}

/// §4.1.97 — `pmu_read` on a thread that is not in `.faulted` or `.suspended` state returns `E_BUSY`.
pub fn main(_: u64) void {
    const pmu = t.requirePmu("§4.1.97");

    const h = syscall.thread_create(&spinLoop, 0, 4);
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    // Remote pmu_start requires target to be .faulted or .suspended.
    if (syscall.thread_suspend(worker_h) != syscall.E_OK) {
        t.fail("§4.1.97 thread_suspend pre-start");
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }
    var cfg = syscall.PmuCounterConfig{ .event = pmu.event, .has_threshold = false, .overflow_threshold = 0 };
    if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§4.1.97 pmu_start");
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_resume(worker_h);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }
    _ = syscall.thread_resume(worker_h);

    var sample: syscall.PmuSample = undefined;
    const rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (rc != syscall.E_BUSY) {
        t.failWithVal("§4.1.97", syscall.E_BUSY, rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    t.pass("§4.1.97");
    @atomicStore(u64, &worker_stop, 1, .seq_cst);
    _ = syscall.pmu_stop(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
