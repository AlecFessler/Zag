const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §3.2.9 — `futex_wait` returns `E_AGAIN` on value mismatch.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var val: u64 = 42;
    // Expected doesn't match actual — should return immediately with E_AGAIN.
    const ret = syscall.futex_wait(&val, 0, 0xFFFFFFFFFFFFFFFF);
    t.expectEqual("§3.2.9", E_AGAIN, ret);
    syscall.shutdown();
}
