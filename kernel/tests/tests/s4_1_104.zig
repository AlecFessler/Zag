const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.104 — `pmu_reset` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };

    const rc_bad = syscall.pmu_reset(t.BOGUS_HANDLE, @intFromPtr(&cfg), 1);
    if (rc_bad != syscall.E_BADHANDLE) {
        t.failWithVal("§4.1.104 bogus", syscall.E_BADHANDLE, rc_bad);
        syscall.shutdown();
    }

    const rc_wrong = syscall.pmu_reset(0, @intFromPtr(&cfg), 1);
    if (rc_wrong != syscall.E_BADHANDLE) {
        t.failWithVal("§4.1.104 wrong-type", syscall.E_BADHANDLE, rc_wrong);
        syscall.shutdown();
    }

    t.pass("§4.1.104");
    syscall.shutdown();
}
