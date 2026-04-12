const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

// §3.3.16 covers two clauses:
//   1. "The process must call reply before calling recv again" — already
//      exercised by the base reply-then-recv discipline (see also §2.11.13
//      for the E_BUSY path). Here we focus on the second clause:
//   2. "The atomic recv flag on reply transitions directly into recv after
//      replying."
//
// Setup: this test process acts as its own IPC server. Two worker threads
// are callers. Worker 1 calls first (gets served by main's first recv),
// worker 2 calls second and is queued. Main then ipc_reply_recv with the
// atomic recv flag — the reply should go to worker 1 and the SAME syscall
// return should dequeue worker 2's message.

var child_ready: u64 align(8) = 0; // bumped by each caller that has queued

fn caller1() void {
    _ = @atomicRmw(u64, &child_ready, .Add, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&child_ready), 1);
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(0, &.{0xAAAA}, &reply);
    syscall.thread_exit();
}

fn caller2() void {
    _ = @atomicRmw(u64, &child_ready, .Add, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&child_ready), 1);
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(0, &.{0xBBBB}, &reply);
    syscall.thread_exit();
}

/// §3.3.16 — The process must call `reply` before calling `recv` again.
pub fn main(_: u64) void {
    _ = syscall.thread_create(&caller1, 0, 4);
    _ = syscall.thread_create(&caller2, 0, 4);

    // Wait for both callers to queue. Each bumps child_ready before
    // entering ipc_call; give them ample yield windows so both reach the
    // kernel wait queue before we recv.
    while (@atomicLoad(u64, &child_ready, .acquire) < 2) {
        syscall.thread_yield();
    }
    for (0..2000) |_| syscall.thread_yield();

    // First recv: dequeue first caller.
    var msg1: syscall.IpcMessage = .{};
    const r1 = syscall.ipc_recv(true, &msg1);
    if (r1 != 0) {
        t.failWithVal("§3.3.16 recv1", 0, r1);
        syscall.shutdown();
    }

    // Atomic reply-recv: reply to the first caller and atomically recv the
    // next message. The second worker should already be queued.
    var msg2: syscall.IpcMessage = .{};
    const r2 = syscall.ipc_reply_recv(&.{msg1.words[0] + 1}, true, &msg2);
    if (r2 != 0) {
        t.failWithVal("§3.3.16 reply_recv", 0, r2);
        syscall.shutdown();
    }

    // Both messages should be 0xAAAA and 0xBBBB in some order.
    const w1 = msg1.words[0];
    const w2 = msg2.words[0];
    const both = (w1 == 0xAAAA and w2 == 0xBBBB) or (w1 == 0xBBBB and w2 == 0xAAAA);
    if (!both) {
        t.fail("§3.3.16 payload mismatch");
        syscall.shutdown();
    }

    // Reply to second caller to let it exit cleanly.
    _ = syscall.ipc_reply(&.{msg2.words[0] + 1});

    t.pass("§3.3.16");
    syscall.shutdown();
}
