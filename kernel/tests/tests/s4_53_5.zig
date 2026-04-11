const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;

fn workerLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (true) syscall.thread_yield();
}

/// §4.53.5 — `pmu_reset` on a thread not in `.faulted` state returns `E_INVAL`.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.53.5");
        syscall.shutdown();
    }

    const h = syscall.thread_create(&workerLoop, 0, 4);
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = @intFromEnum(syscall.PmuEvent.cycles) };
    _ = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);

    // Suspended (not faulted) — §4.53.5 requires this to fail.
    _ = syscall.thread_suspend(worker_h);
    const rc = syscall.pmu_reset(worker_h, @intFromPtr(&cfg), 1);
    t.expectEqual("§4.53.5", syscall.E_INVAL, rc);

    _ = syscall.pmu_stop(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
