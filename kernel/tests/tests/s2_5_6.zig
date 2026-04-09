const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var futex_val: u64 align(8) = 0;
var woken_count: u64 align(8) = 0;

fn waiter() void {
    const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, MAX_TIMEOUT);
    // Atomic increment of woken_count.
    while (true) {
        const current = @as(*u64, @ptrCast(&woken_count)).*;
        const result = @cmpxchgWeak(u64, &woken_count, current, current + 1, .seq_cst, .seq_cst);
        if (result == null) break;
    }
    _ = syscall.futex_wake(@ptrCast(&woken_count), 10);
    // Stay alive.
    while (true) {
        syscall.thread_yield();
    }
}

/// §2.5.6 — `futex_wake` wakes up to `count` threads blocked on `addr`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Create 3 waiters.
    _ = syscall.thread_create(&waiter, 0, 4);
    _ = syscall.thread_create(&waiter, 0, 4);
    _ = syscall.thread_create(&waiter, 0, 4);
    // Let all 3 block on futex.
    syscall.thread_yield();
    syscall.thread_yield();
    syscall.thread_yield();
    // Wake only 2.
    const woke = syscall.futex_wake(@ptrCast(&futex_val), 2);
    // Wait for the 2 to report in.
    t.waitUntilAtLeast(&woken_count, 2);
    // Give a moment to check no extra thread woke.
    syscall.thread_yield();
    syscall.thread_yield();
    if (woke == 2 and woken_count == 2) {
        t.pass("§2.5.6");
    } else {
        t.fail("§2.5.6");
    }
    syscall.shutdown();
}
