const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §3.2.20 — `futex_wait_change` with `count` exceeding `MAX_FUTEX_WAIT` (64) returns `E_INVAL`.
pub fn main(_: u64) void {
    var addrs = [1]u64{0};
    const ret = syscall.futex_wait_change(@intFromPtr(&addrs), 65, 0);
    t.expectEqual("§3.2.20", syscall.E_INVAL, ret);
    syscall.shutdown();
}
