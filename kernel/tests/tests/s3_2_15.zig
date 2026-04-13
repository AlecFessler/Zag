const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var futex_val: u64 align(8) = 0;

fn changer() void {
    syscall.thread_yield();
    syscall.thread_yield();
    @atomicStore(u64, &futex_val, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);
}

/// §3.2.15 — `futex_wait_change` returns the index (non-negative) of the first address that changed on success.
pub fn main(_: u64) void {
    _ = syscall.thread_create(&changer, 0, 4);
    var addrs = [1]u64{@intFromPtr(&futex_val)};
    const ret = syscall.futex_wait_change(@intFromPtr(&addrs), 1, @bitCast(@as(i64, -1)));
    // With count=1, the only valid success index is 0.
    t.expectEqual("§3.2.15", 0, ret);
    syscall.shutdown();
}
