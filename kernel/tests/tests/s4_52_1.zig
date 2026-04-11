const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;

fn workerLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (true) syscall.thread_yield();
}

/// §4.52.1 — `pmu_read` returns `E_OK` on success.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.52.1");
        syscall.shutdown();
    }

    const h = syscall.thread_create(&workerLoop, 0, 4);
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = @intFromEnum(syscall.PmuEvent.cycles) };
    _ = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);
    for (0..100) |_| syscall.thread_yield();
    _ = syscall.thread_suspend(worker_h);

    var sample: syscall.PmuSample = undefined;
    const rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (rc != syscall.E_OK) {
        t.failWithVal("§4.52.1", syscall.E_OK, rc);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }
    if (sample.counters[0] == 0) {
        t.fail("§4.52.1 counter zero after run");
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }
    if (sample.timestamp == 0) {
        t.fail("§4.52.1 timestamp zero");
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    t.pass("§4.52.1");
    _ = syscall.pmu_stop(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
