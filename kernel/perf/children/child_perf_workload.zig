const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Tight compute workload for profiler testing.
/// 1. Spawns a park thread (multi-threaded required for external fault handler).
/// 2. First IPC round: replies with hot loop + main addresses.
/// 3. Second IPC round: cap-transfers `fault_handler` to the parent so PMU
///    overflow faults deliver to the parent's fault_box instead of this
///    process's own (unread) fault_box. Matches the pattern in
///    `child_pmu_overflow.zig`.
/// 4. Starts PMU with overflow threshold on self.
/// 5. Runs the hot loop until faulted by overflow.
pub fn main(_: u64) void {
    // Must be multi-threaded for overflow faults to deliver to external handler
    _ = syscall.thread_create(&parkLoop, 0, 4);

    // First round: return addresses. The kernel cap-transfer reply format
    // is {handle, rights} only (2 words, no payload), so we can't fold
    // this into the cap-transfer reply itself.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const loop_addr = @intFromPtr(&hotLoop);
    const main_addr = @intFromPtr(&main);
    _ = syscall.ipc_reply(&.{ loop_addr, main_addr });

    // Second round: cap-transfer HANDLE_SELF with fault_handler rights.
    // This sets `fault_handler_proc = parent` in the kernel so PMI-overflow
    // faults route to the parent.
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const fh_rights = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, fh_rights });

    // Start PMU with overflow threshold
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK) {
        syscall.thread_exit();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        syscall.thread_exit();
    };

    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{
        .event = evt,
        .has_threshold = true,
        .overflow_threshold = 10000,
    };
    _ = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);

    // Run the hot loop — will be interrupted by PMU overflow faults
    // that the parent collects and resumes
    hotLoop();

    syscall.thread_exit();
}

fn parkLoop() void {
    while (true) syscall.thread_yield();
}

fn hotLoop() void {
    var accumulator: u64 = 0;
    var i: u64 = 0;
    while (i < 100_000_000) {
        accumulator +%= i;
        accumulator ^= (accumulator << 3);
        i += 1;
    }
    // Prevent dead code elimination
    if (accumulator == 0x1234_5678_9ABC_DEF0) {
        syscall.write("x");
    }
}
