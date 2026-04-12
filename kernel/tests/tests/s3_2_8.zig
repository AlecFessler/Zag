const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var futex_val: u64 align(8) = 0;

fn waker() void {
    // Give main thread time to enter futex_wait.
    syscall.thread_yield();
    syscall.thread_yield();
    @atomicStore(u64, &futex_val, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);
}

/// §3.2.8 — `futex_wait` returns `E_OK` when woken.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    _ = syscall.thread_create(&waker, 0, 4);
    const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
    const ret = syscall.futex_wait(@ptrCast(&futex_val), 0, MAX_TIMEOUT);
    t.expectEqual("§3.2.8", 0, ret);
    syscall.shutdown();
}
