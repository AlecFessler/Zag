const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §3.2.19 — `futex_wait_change` with `count = 0` returns `E_INVAL`.
pub fn main(_: u64) void {
    var addrs = [1]u64{0};
    const ret = syscall.futex_wait_change(@intFromPtr(&addrs), 0, 0);
    t.expectEqual("§3.2.19", syscall.E_INVAL, ret);
    syscall.shutdown();
}
