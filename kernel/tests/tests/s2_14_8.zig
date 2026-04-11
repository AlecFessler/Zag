const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var helper_ready: u64 align(8) = 0;

fn helperLoop() void {
    @atomicStore(u64, &helper_ready, 1, .seq_cst);
    while (true) syscall.thread_yield();
}

/// §2.14.8 — PMU state on a thread is created lazily.
pub fn main(_: u64) void {
    // Spawn a helper thread that NEVER calls pmu_start. Any pmu_read or
    // pmu_stop on it must report "no PMU state" (E_INVAL) — proof that
    // allocation is deferred until pmu_start is actually called.
    const worker = syscall.thread_create(&helperLoop, 0, 4);
    if (worker <= 0) {
        t.failWithVal("§2.14.8 thread_create", 1, worker);
        syscall.shutdown();
    }
    const worker_h: u64 = @bitCast(worker);

    while (@atomicLoad(u64, &helper_ready, .seq_cst) == 0) syscall.thread_yield();
    _ = syscall.thread_suspend(worker_h);

    var sample: syscall.PmuSample = undefined;
    const read_rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (read_rc != syscall.E_INVAL) {
        t.failWithVal("§2.14.8 pmu_read lazy", syscall.E_INVAL, read_rc);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    const stop_rc = syscall.pmu_stop(worker_h);
    if (stop_rc != syscall.E_INVAL) {
        t.failWithVal("§2.14.8 pmu_stop lazy", syscall.E_INVAL, stop_rc);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    // After pmu_start + pmu_stop round trip, the state should be freed
    // and subsequent pmu_read must again return E_INVAL.
    var info: syscall.PmuInfo = undefined;
    _ = syscall.pmu_info(@intFromPtr(&info));
    if (info.num_counters > 0) {
        var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
        if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
            t.fail("§2.14.8 pmu_start");
            _ = syscall.thread_kill(worker_h);
            syscall.shutdown();
        }
        if (syscall.pmu_stop(worker_h) != syscall.E_OK) {
            t.fail("§2.14.8 pmu_stop after start");
            _ = syscall.thread_kill(worker_h);
            syscall.shutdown();
        }
        const read_after = syscall.pmu_read(worker_h, @intFromPtr(&sample));
        if (read_after != syscall.E_INVAL) {
            t.failWithVal("§2.14.8 pmu_read after stop", syscall.E_INVAL, read_after);
            _ = syscall.thread_kill(worker_h);
            syscall.shutdown();
        }
    }

    t.pass("§2.14.8");
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
