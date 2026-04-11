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
    // within a handful of retired events. Use the first supported event
    // from `pmu_info` so the test works on rigs whose overflow-capable
    // counters do not include `.instructions`.
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK) syscall.thread_exit();
    const evt = syscall.pickSupportedEvent(info) orelse {
        syscall.thread_exit();
    };

    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{
        .event = evt,
        .has_threshold = true,
        .overflow_threshold = 1024,
    };
    _ = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);

    // Burn cycles until the overflow faults us. Bound the loop so a
    // kernel regression (overflow never delivered) surfaces as a
    // thread_exit rather than a QEMU timeout — the parent test can
    // then fail with a clear diagnostic.
    var x: u64 = 0;
    while (x < 10_000_000) : (x +%= 1) {}
    syscall.thread_exit();
}
