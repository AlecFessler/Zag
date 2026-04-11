const lib = @import("lib");

const syscall = lib.syscall;

/// Child spawned WITH `ProcessRights.pmu` but whose initial thread handle
/// lacks `ThreadHandleRights.pmu`. Tries all four thread-operating PMU
/// syscalls on its own thread_self handle and reports each return code
/// over IPC. The parent verifies every one is `E_PERM` (§2.14.2).
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const self_thread: u64 = @bitCast(syscall.thread_self());

    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
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
