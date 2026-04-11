const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;

fn workerLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (true) syscall.thread_yield();
}

/// §4.52.6 — `pmu_read` on a thread that has no PMU state (no prior `pmu_start`) returns `E_INVAL`.
pub fn main(_: u64) void {
    const h = syscall.thread_create(&workerLoop, 0, 4);
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    _ = syscall.thread_suspend(worker_h);
    var sample: syscall.PmuSample = undefined;
    const rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    t.expectEqual("§4.52.6", syscall.E_INVAL, rc);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
