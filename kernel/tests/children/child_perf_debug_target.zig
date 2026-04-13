const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Debugger round-trip target. Must stay multi-threaded (park thread) so
/// an external fault handler receives our breakpoint faults.
///
/// Protocol with parent:
///   1. Park thread created.
///   2. First IPC: report `&hotLoop` address so parent can compute the
///      byte offset to patch with `0xCC` (int3).
///   3. Second IPC: cap-transfer `fault_handler` to parent.
///   4. Enter hotLoop — a trivial function the parent breakpoints. When
///      the parent writes 0xCC at hotLoop's first byte, the next call
///      traps; parent restores the byte, rewinds rip, and resumes. Child
///      executes the restored instruction, returns from hotLoop, and the
///      outer loop calls it again. On the next iteration the parent
///      re-inserts the breakpoint so the cycle repeats.
pub fn main(_: u64) void {
    // Pin to same core as parent so the parent's REALTIME priority
    // reliably preempts us after each fault_reply — prevents us from
    // racing past the restored byte and re-entering hotLoop before
    // parent re-inserts the breakpoint. Best-effort: if set_affinity
    // isn't granted we fall through and accept noisier measurements.
    _ = syscall.set_affinity(1);

    _ = syscall.thread_create(&parkLoop, 0, 4);

    // Round 1: report hot loop address.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{@intFromPtr(&hotLoop)});

    // Round 2: cap-transfer fault_handler to parent.
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const fh_rights = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, fh_rights });

    // Drive the debugger loop. Each call to `hotLoop` enters a function
    // whose first byte the parent can breakpoint. On trap the parent
    // restores, rewinds rip, and resumes — the function completes
    // normally, returns, and we loop back.
    while (true) {
        asm volatile ("" : : [ptr] "r" (&hotLoop) : .{ .memory = true });
        hotLoop();
    }
}

fn parkLoop() void {
    while (true) syscall.thread_yield();
}

/// Breakpoint target. Parent reads the first byte via `fault_read_mem`
/// at runtime so the exact prologue doesn't matter — parent restores
/// whatever was there before patching 0xCC in.
fn hotLoop() void {
    asm volatile ("nop" ::: .{ .memory = true });
}
