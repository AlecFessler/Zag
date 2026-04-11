const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_counter: u64 align(8) = 0;

fn workerLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (true) {
        _ = @atomicRmw(u64, &worker_counter, .Add, 1, .seq_cst);
        syscall.thread_yield();
    }
}

/// §2.14.7 — `PmuSample.timestamp` is a monotonic nanosecond reading consistent with `clock_gettime`, sampled at the moment the counters are read.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§2.14.7");
        syscall.shutdown();
    }

    const worker = syscall.thread_create(&workerLoop, 0, 4);
    if (worker <= 0) {
        t.failWithVal("§2.14.7 thread_create", 1, worker);
        syscall.shutdown();
    }
    const worker_h: u64 = @bitCast(worker);

    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
    if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§2.14.7 pmu_start");
        syscall.shutdown();
    }

    // Let the worker run, then suspend and read timestamps.
    for (0..100) |_| syscall.thread_yield();
    if (syscall.thread_suspend(worker_h) != syscall.E_OK) {
        t.fail("§2.14.7 thread_suspend");
        syscall.shutdown();
    }

    const ts_before: i64 = syscall.clock_gettime();
    var sample: syscall.PmuSample = undefined;
    sample.timestamp = 0;
    const rd = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    const ts_after: i64 = syscall.clock_gettime();
    if (rd != syscall.E_OK) {
        t.failWithVal("§2.14.7 pmu_read", syscall.E_OK, rd);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    const sample_ts: i64 = @bitCast(sample.timestamp);
    if (sample_ts < ts_before or sample_ts > ts_after) {
        t.failWithVal("§2.14.7 timestamp out of bracket", ts_before, sample_ts);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    t.pass("§2.14.7");
    _ = syscall.pmu_stop(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
