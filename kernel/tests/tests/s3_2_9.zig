const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §3.2.9 — `futex_wait_val` returns the index of the mismatched address immediately when any `addrs[i]` does not match `expected[i]` at call time.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var val: u64 = 42;
    // Expected doesn't match actual — should return immediately with the index (0) of the mismatched address.
    const ret = syscall.futex_wait(&val, 0, 0xFFFFFFFFFFFFFFFF);
    t.expectEqual("§3.2.9", @as(i64, 0), ret);
    syscall.shutdown();
}
