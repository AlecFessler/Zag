const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Child spawns an extra worker thread so the process is multi-threaded,
/// cap-transfers fault_handler to the parent, then starts PMU on itself
/// with a tiny overflow threshold and spins until the overflow fires.
///
/// The parent is expected to receive a `pmu_overflow` fault on the
/// main thread and call `fault_reply(FAULT_KILL)` to tear us down.
fn parkLoop() void {
    while (true) syscall.thread_yield();
}

pub fn main(_: u64) void {
    // Multi-threaded so single-thread-self-handler kill (§2.14.14) does
    // not apply — we want the overflow to deliver to the external handler.
    _ = syscall.thread_create(&parkLoop, 0, 4);

    // Cap-transfer fault_handler to the parent.
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    // Start PMU with a small overflow threshold so a counter overflows
    // within a handful of retired instructions.
    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{
        .event = @intFromEnum(syscall.PmuEvent.instructions),
        .overflow_threshold = 1024,
    };
    _ = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);

    // Burn cycles until the overflow faults us.
    var x: u64 = 0;
    while (true) : (x +%= 1) {}
}
