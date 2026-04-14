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

/// §3.2.3 — `futex_wait_val` with timeout=`MAX_U64` blocks indefinitely until woken.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    _ = syscall.thread_create(&waker, 0, 4);
    const MAX_U64: u64 = @bitCast(@as(i64, -1));
    const ret = syscall.futex_wait(@ptrCast(&futex_val), 0, MAX_U64);
    // Should have been woken (E_OK), not timed out.
    t.expectEqual("§3.2.3", 0, ret);
    syscall.shutdown();
}
