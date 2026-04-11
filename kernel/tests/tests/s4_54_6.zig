const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_exit: u64 align(8) = 0;

fn shortWorker() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_exit, .seq_cst) == 0) syscall.thread_yield();
    syscall.thread_exit();
}

/// §4.54.6 — A thread's PMU state is automatically released on thread exit, so an explicit `pmu_stop` is not required before exit.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.54.6");
        syscall.shutdown();
    }

    const h = syscall.thread_create(&shortWorker, 0, 4);
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
    if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§4.54.6 pmu_start");
        syscall.shutdown();
    }

    // Tell worker to exit. The kernel must free its PMU state without
    // requiring an explicit pmu_stop.
    @atomicStore(u64, &worker_exit, 1, .seq_cst);
    while (syscall.revoke_perm(worker_h) != syscall.E_BADHANDLE) {
        syscall.thread_yield();
    }

    t.pass("§4.54.6");
    syscall.shutdown();
}
