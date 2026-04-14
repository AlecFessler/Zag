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

    // Burn cycles until the overflow faults us. The loop is unbounded
    // on purpose: under `PARALLEL=8` the host is oversubscribed and KVM
    // can defer virtual-PMI injection long past any fixed iteration
    // budget, causing the child to finish its work loop before the
    // overflow ever reflects into the guest — which then surfaces as
    // either a `thread_exit`-induced hang in the parent's blocking
    // `fault_recv` or (for the self-handler variant) a spurious
    // `illegal_instruction` trailer. If PMU delivery is truly broken,
    // the per-assertion QEMU timeout in `run_tests.sh` is our backstop.
    while (true) {
        switch (@import("builtin").cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => {},
        }
    }
}
