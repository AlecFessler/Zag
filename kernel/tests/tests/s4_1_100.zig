const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;

fn workerLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (true) syscall.thread_yield();
}

/// §4.1.100 — Counter entries beyond `PmuInfo.num_counters` in the returned `PmuSample` are zero.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.1.100");
        syscall.shutdown();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        t.pass("§4.1.100");
        syscall.shutdown();
    };

    const h = syscall.thread_create(&workerLoop, 0, 4);
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = evt, .has_threshold = false, .overflow_threshold = 0 };
    _ = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);
    for (0..100) |_| syscall.thread_yield();
    _ = syscall.thread_suspend(worker_h);

    var sample: syscall.PmuSample = undefined;
    // Pre-poison every slot. The kernel must zero slots beyond num_counters.
    for (&sample.counters) |*c| c.* = 0xdead_beef;
    if (syscall.pmu_read(worker_h, @intFromPtr(&sample)) != syscall.E_OK) {
        t.fail("§4.1.100 pmu_read");
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    var i: usize = info.num_counters;
    while (i < syscall.PMU_MAX_COUNTERS) : (i += 1) {
        if (sample.counters[i] != 0) {
            t.fail("§4.1.100 slot beyond num_counters not zero");
            _ = syscall.thread_kill(worker_h);
            syscall.shutdown();
        }
    }

    t.pass("§4.1.100");
    _ = syscall.pmu_stop(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
