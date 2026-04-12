const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.89 — `pmu_start` with a non-null `overflow_threshold` when `PmuInfo.overflow_support` is false returns `E_INVAL`.
///
/// Two cases, chosen by the rig's `overflow_support` flag:
///
///   * `overflow_support == false`: exercise the documented negative
///     path — `has_threshold = true` + supported event on `thread_self`
///     must return `E_INVAL`.
///
///   * `overflow_support == true`: exercise the positive counterpart —
///     the same call on a worker thread must succeed. This catches
///     regressions where the kernel incorrectly rejects valid overflow
///     configs on a rig that advertises overflow support.
///
/// The positive branch must NOT run on `thread_self` in a single-threaded
/// self-handling process: per §2.14.14, a PMU overflow fault in that
/// topology kills the process, and a race between `pmu_start` and
/// `pmu_stop` under slow QEMU scheduling could silently kill the test.
/// We spawn a helper worker thread so the parent's fault handler (the
/// kernel default) remains outside the target thread, and we use
/// `overflow_threshold = max u64` so overflow is effectively impossible
/// between `pmu_start` and `pmu_stop`.
var worker_ready: u64 align(8) = 0;
var worker_stop: u64 align(8) = 0;

fn workerLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_stop, .seq_cst) == 0) syscall.thread_yield();
}

pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.1.89");
        syscall.shutdown();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        t.pass("§4.1.89");
        syscall.shutdown();
    };

    if (info.overflow_support) {
        // Positive path: spawn a helper worker and start PMU on it with
        // a max-threshold has_threshold=true config. Overflow is
        // effectively impossible before pmu_stop fires. Even if it did,
        // the worker is a separate thread in this process, so the fault
        // would route to the parent's handler (the kernel default) per
        // §2.12.x, not kill the test.
        const h = syscall.thread_create(&workerLoop, 0, 4);
        if (h <= 0) {
            t.failWithVal("§4.1.89 thread_create", 1, h);
            syscall.shutdown();
        }
        const worker_h: u64 = @bitCast(h);
        while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

        var cfg = syscall.PmuCounterConfig{
            .event = evt,
            .has_threshold = true,
            .overflow_threshold = ~@as(u64, 0),
        };
        const rc = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);
        if (rc != syscall.E_OK) {
            t.failWithVal("§4.1.89 overflow-supported positive", syscall.E_OK, rc);
            @atomicStore(u64, &worker_stop, 1, .seq_cst);
            _ = syscall.thread_kill(worker_h);
            syscall.shutdown();
        }
        _ = syscall.pmu_stop(worker_h);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        t.pass("§4.1.89");
    } else {
        // Negative path: no worker needed. overflow_support == false, so
        // the call returns E_INVAL before any counter is armed.
        const self_thread: u64 = @bitCast(syscall.thread_self());
        var cfg = syscall.PmuCounterConfig{
            .event = evt,
            .has_threshold = true,
            .overflow_threshold = 1_000_000,
        };
        const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
        t.expectEqual("§4.1.89", syscall.E_INVAL, rc);
    }
    syscall.shutdown();
}
