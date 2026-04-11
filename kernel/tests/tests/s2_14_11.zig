const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_stop: u64 align(8) = 0;

fn spinLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_stop, .seq_cst) == 0) syscall.thread_yield();
}

/// §2.14.11 — `pmu_read` is only valid when the target thread is in `.faulted` or `.suspended` state.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§2.14.11");
        syscall.shutdown();
    }

    const worker = syscall.thread_create(&spinLoop, 0, 4);
    const worker_h: u64 = @bitCast(worker);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = @intFromEnum(syscall.PmuEvent.cycles) };
    _ = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);

    // Running thread → E_BUSY.
    var sample: syscall.PmuSample = undefined;
    const busy_rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (busy_rc != syscall.E_BUSY) {
        t.failWithVal("§2.14.11 running", syscall.E_BUSY, busy_rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    // Suspended thread → E_OK.
    _ = syscall.thread_suspend(worker_h);
    const suspended_rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (suspended_rc != syscall.E_OK) {
        t.failWithVal("§2.14.11 suspended", syscall.E_OK, suspended_rc);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    t.pass("§2.14.11");
    @atomicStore(u64, &worker_stop, 1, .seq_cst);
    _ = syscall.pmu_stop(worker_h);
    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}
