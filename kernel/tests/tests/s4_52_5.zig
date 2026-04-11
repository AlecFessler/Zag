const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_stop: u64 align(8) = 0;

fn spinLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_stop, .seq_cst) == 0) syscall.thread_yield();
}

/// §4.52.5 — `pmu_read` on a thread that is not in `.faulted` or `.suspended` state returns `E_BUSY`.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.52.5");
        syscall.shutdown();
    }

    const h = syscall.thread_create(&spinLoop, 0, 4);
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
    _ = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);

    var sample: syscall.PmuSample = undefined;
    const rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (rc != syscall.E_BUSY) {
        t.failWithVal("§4.52.5", syscall.E_BUSY, rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    t.pass("§4.52.5");
    @atomicStore(u64, &worker_stop, 1, .seq_cst);
    _ = syscall.pmu_stop(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
