const lib = @import("lib");

const syscall = lib.syscall;

/// Child spawned without `ProcessRights.pmu`. Tries all four thread-operating
/// PMU syscalls on its own thread and reports the four return codes via IPC
/// reply so the parent can verify every one is `E_PERM` (§2.14.1).
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const self_thread: u64 = @bitCast(syscall.thread_self());

    // Attempt to use a supported event for the config. This child has no
    // `ProcessRights.pmu` so `pmu_info` itself may return `E_PERM`; if
    // that happens we fall back to `.cycles`. The E_PERM assertion in
    // the parent does not depend on which event is used — the rights
    // check short-circuits before event validation — but using the
    // helper keeps all PMU tests consistent per §2.14.
    var info: syscall.PmuInfo = undefined;
    const info_rc = syscall.pmu_info(@intFromPtr(&info));
    const evt: syscall.PmuEvent = if (info_rc == syscall.E_OK)
        (syscall.pickSupportedEvent(info) orelse .cycles)
    else
        .cycles;

    var cfg = syscall.PmuCounterConfig{ .event = evt, .has_threshold = false, .overflow_threshold = 0 };
    const start_rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);

    var sample: syscall.PmuSample = undefined;
    const read_rc = syscall.pmu_read(self_thread, @intFromPtr(&sample));

    const reset_rc = syscall.pmu_reset(self_thread, @intFromPtr(&cfg), 1);

    const stop_rc = syscall.pmu_stop(self_thread);

    _ = syscall.ipc_reply(&.{
        @bitCast(start_rc),
        @bitCast(read_rc),
        @bitCast(reset_rc),
        @bitCast(stop_rc),
    });
}
