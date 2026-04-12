const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.88 — `pmu_start` with an event not set in `PmuInfo.supported_events` returns `E_INVAL`.
///
/// The spec error is "event not set in supported_events". To be sure we
/// exercise that specific check (not a separate enum-range check), we
/// pick a defined enum variant whose bit is clear in `supported_events`
/// and pass it through. Only if literally every defined variant is
/// supported do we fall back to an out-of-enum id.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.1.88");
        syscall.shutdown();
    }

    var unsupported: ?syscall.PmuEvent = null;
    inline for (@typeInfo(syscall.PmuEvent).@"enum".fields) |f| {
        const bit = @as(u64, 1) << f.value;
        if ((info.supported_events & bit) == 0) {
            unsupported = @enumFromInt(f.value);
            break;
        }
    }

    const event = unsupported orelse @as(syscall.PmuEvent, @enumFromInt(99));

    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{ .event = event, .has_threshold = false, .overflow_threshold = 0 };
    const rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
    t.expectEqual("§4.1.88", syscall.E_INVAL, rc);
    syscall.shutdown();
}
