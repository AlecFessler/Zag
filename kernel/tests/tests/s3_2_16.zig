const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var futex_val: u64 align(8) = 0;

/// §3.2.16 — `futex_wait_change` returns `E_TIMEOUT` on timeout expiry.
pub fn main(_: u64) void {
    var addrs = [1]u64{@intFromPtr(&futex_val)};
    // Use a small timeout; value won't change so it should time out.
    const ret = syscall.futex_wait_change(@intFromPtr(&addrs), 1, 1_000_000);
    t.expectEqual("§3.2.16", syscall.E_TIMEOUT, ret);
    syscall.shutdown();
}
