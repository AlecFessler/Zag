const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var futex_val: u64 align(8) = 0;

fn waker() void {
    syscall.thread_yield();
    syscall.thread_yield();
    futex_val = 1;
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);
}

/// §2.5.1 — `futex_wait` blocks the calling thread when value at `addr` matches `expected`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    _ = syscall.thread_create(&waker, 0, 4);
    // Block until waker changes the value and wakes us.
    const ret = syscall.futex_wait(@ptrCast(&futex_val), 0, @bitCast(@as(i64, -1)));
    // If we were woken (not timed out), the value should have changed.
    if (ret == 0 and futex_val == 1) {
        t.pass("§2.5.1");
    } else {
        t.fail("§2.5.1");
    }
    syscall.shutdown();
}
