const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_stop: u64 align(8) = 0;

fn worker() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_stop, .seq_cst) == 0) syscall.thread_yield();
}

/// §4.54.1 — `pmu_stop` returns `E_OK` on success.
///
/// Positive path also observably verifies "state freed": after `pmu_stop`,
/// `pmu_read` on the same (suspended) target returns `E_INVAL` because the
/// PMU state slot was released back to the allocator. To do that we need
/// the target to be `.suspended` (otherwise `pmu_read` returns `E_BUSY` on
/// a running thread per §2.14.11) — hence a helper worker rather than
/// self-thread.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.54.1");
        syscall.shutdown();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        t.pass("§4.54.1");
        syscall.shutdown();
    };

    const h = syscall.thread_create(&worker, 0, 4);
    if (h <= 0) {
        t.failWithVal("§4.54.1 thread_create", 1, h);
        syscall.shutdown();
    }
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = evt, .has_threshold = false, .overflow_threshold = 0 };
    if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§4.54.1 pmu_start");
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    // Suspend so pmu_stop + subsequent pmu_read are both valid on the
    // thread (running threads would return E_BUSY on pmu_read).
    _ = syscall.thread_suspend(worker_h);

    const rc = syscall.pmu_stop(worker_h);
    if (rc != syscall.E_OK) {
        t.failWithVal("§4.54.1 pmu_stop", syscall.E_OK, rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    // After stop, the thread has no PMU state — pmu_read must return
    // E_INVAL. This is the observable "state freed" proof.
    var sample: syscall.PmuSample = undefined;
    const read_rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (read_rc != syscall.E_INVAL) {
        t.failWithVal("§4.54.1 pmu_read after stop", syscall.E_INVAL, read_rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_resume(worker_h);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    t.pass("§4.54.1");
    @atomicStore(u64, &worker_stop, 1, .seq_cst);
    _ = syscall.thread_resume(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
