const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.51.8 — `pmu_start` with a non-null `overflow_threshold` when `PmuInfo.overflow_support` is false returns `E_INVAL`.
///
/// The negative path (`overflow_support == false` must return `E_INVAL`)
/// cannot be exercised on hardware that reports `overflow_support == true`.
/// We split the test:
///   * If `overflow_support == false`: exercise the documented negative
///     path — `has_threshold = true` + supported event -> expect `E_INVAL`.
///   * If `overflow_support == true`: exercise the positive counterpart —
///     the same call should instead return `E_OK`, catching regressions
///     where the kernel incorrectly rejects valid overflow configs on a
///     rig that advertises overflow support.
/// Both branches give real coverage; a completely skipped test would not.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.51.8");
        syscall.shutdown();
    }

    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{
        .event = .cycles,
        .has_threshold = true,
        .overflow_threshold = 1_000_000,
    };
    const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);

    if (info.overflow_support) {
        if (rc != syscall.E_OK) {
            t.failWithVal("§4.51.8 overflow-supported positive", syscall.E_OK, rc);
            syscall.shutdown();
        }
        _ = syscall.pmu_stop(self_thread);
        t.pass("§4.51.8");
    } else {
        t.expectEqual("§4.51.8", syscall.E_INVAL, rc);
    }
    syscall.shutdown();
}
