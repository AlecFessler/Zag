const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.51.4 — `pmu_start` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    var cfg = syscall.PmuCounterConfig{ .event = @intFromEnum(syscall.PmuEvent.cycles) };

    // Bogus handle ID — never allocated.
    const rc_bad = syscall.pmu_start(0xdead_beef, @intFromPtr(&cfg), 1);
    if (rc_bad != syscall.E_BADHANDLE) {
        t.failWithVal("§4.51.4 bogus", syscall.E_BADHANDLE, rc_bad);
        syscall.shutdown();
    }

    // Slot 0 (HANDLE_SELF) is a PROCESS entry, not a thread entry.
    const rc_wrong = syscall.pmu_start(0, @intFromPtr(&cfg), 1);
    if (rc_wrong != syscall.E_BADHANDLE) {
        t.failWithVal("§4.51.4 wrong-type", syscall.E_BADHANDLE, rc_wrong);
        syscall.shutdown();
    }

    t.pass("§4.51.4");
    syscall.shutdown();
}
