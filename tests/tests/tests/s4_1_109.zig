const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_stop: u64 align(8) = 0;

fn worker() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_stop, .seq_cst) == 0) syscall.thread_yield();
}

/// §4.1.109 — `pmu_stop` returns `E_OK` on success.
///
/// Positive path also observably verifies "state freed": after `pmu_stop`,
/// `pmu_read` on the same (suspended) target returns `E_INVAL` because the
/// PMU state slot was released back to the allocator. To do that we need
/// the target to be `.suspended` (otherwise `pmu_read` returns `E_BUSY` on
/// a running thread per §2.14.11) — hence a helper worker rather than
/// self-thread.
pub fn main(_: u64) void {
    const pmu = t.requirePmu("§4.1.109");

    const h = syscall.thread_create(&worker, 0, 4);
    if (h <= 0) {
        t.failWithVal("§4.1.109 thread_create", 1, h);
        syscall.shutdown();
    }
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    // Remote pmu_start requires target to be .faulted or .suspended. The
    // worker needs to stay suspended through pmu_stop + pmu_read below, so
    // we just leave it suspended and never resume.
    if (syscall.thread_suspend(worker_h) != syscall.E_OK) {
        t.fail("§4.1.109 thread_suspend pre-start");
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }
    var cfg = syscall.PmuCounterConfig{ .event = pmu.event, .has_threshold = false, .overflow_threshold = 0 };
    if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§4.1.109 pmu_start");
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_resume(worker_h);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    const rc = syscall.pmu_stop(worker_h);
    if (rc != syscall.E_OK) {
        t.failWithVal("§4.1.109 pmu_stop", syscall.E_OK, rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    // After stop, the thread has no PMU state — pmu_read must return
    // E_INVAL. This is the observable "state freed" proof.
    var sample: syscall.PmuSample = undefined;
    const read_rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (read_rc != syscall.E_INVAL) {
        t.failWithVal("§4.1.109 pmu_read after stop", syscall.E_INVAL, read_rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_resume(worker_h);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    t.pass("§4.1.109");
    @atomicStore(u64, &worker_stop, 1, .seq_cst);
    _ = syscall.thread_resume(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
