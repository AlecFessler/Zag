const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.112 — `pmu_stop` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    const rc_bad = syscall.pmu_stop(t.BOGUS_HANDLE);
    if (rc_bad != syscall.E_BADHANDLE) {
        t.failWithVal("§4.1.112 bogus", syscall.E_BADHANDLE, rc_bad);
        syscall.shutdown();
    }

    const rc_wrong = syscall.pmu_stop(0);
    if (rc_wrong != syscall.E_BADHANDLE) {
        t.failWithVal("§4.1.112 wrong-type", syscall.E_BADHANDLE, rc_wrong);
        syscall.shutdown();
    }

    t.pass("§4.1.112");
    syscall.shutdown();
}
