const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.52.4 — `pmu_read` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    var sample: syscall.PmuSample = undefined;

    const rc_bad = syscall.pmu_read(t.BOGUS_HANDLE, @intFromPtr(&sample));
    if (rc_bad != syscall.E_BADHANDLE) {
        t.failWithVal("§4.52.4 bogus", syscall.E_BADHANDLE, rc_bad);
        syscall.shutdown();
    }

    // Slot 0 is PROCESS not THREAD — wrong type.
    const rc_wrong = syscall.pmu_read(0, @intFromPtr(&sample));
    if (rc_wrong != syscall.E_BADHANDLE) {
        t.failWithVal("§4.52.4 wrong-type", syscall.E_BADHANDLE, rc_wrong);
        syscall.shutdown();
    }

    t.pass("§4.52.4");
    syscall.shutdown();
}
