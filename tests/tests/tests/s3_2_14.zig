const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §3.2.14 — `futex_wait_val` with `count` exceeding `MAX_FUTEX_WAIT` (64) returns `E_INVAL`.
pub fn main(_: u64) void {
    var addrs = [1]u64{0};
    var expected = [1]u64{0};
    const ret = syscall.futex_wait_val(@intFromPtr(&addrs), @intFromPtr(&expected), 65, 0);
    t.expectEqual("§3.2.14", syscall.E_INVAL, ret);
    syscall.shutdown();
}
