const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var futex_val: u64 align(8) = 0;

fn waiterThread() void {
    // Wait on futex_val while it equals 0 (no timeout)
    _ = syscall.futex_wait(&futex_val, 0, @bitCast(@as(i64, -1)));
}

/// §3.2.22 — `futex_wake` returns number of threads woken (non-negative).
pub fn main(_: u64) void {
    // Test 1: wake with no waiters returns 0
    const ret0 = syscall.futex_wake(&futex_val, 1);
    t.expectEqual("§3.2.22 no-waiters", 0, ret0);
    // Test 2: spawn a waiter thread, then wake it — should return 1
    const trc = syscall.thread_create(&waiterThread, 0, 4);
    if (trc < 0) {
        t.fail("§3.2.22 thread_create");
        syscall.shutdown();
    }
    // Yield to let waiter block on futex
    syscall.thread_yield();
    syscall.thread_yield();
    syscall.thread_yield();
    const ret1 = syscall.futex_wake(&futex_val, 1);
    t.expectEqual("§3.2.22 one-waiter", 1, ret1);
    syscall.shutdown();
}
