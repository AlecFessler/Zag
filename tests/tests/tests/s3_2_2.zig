const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_TIMEOUT: i64 = -8;

/// §3.2.2 — `futex_wait_val` with timeout=0 is non-blocking: returns immediately without blocking (try-only check).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var val: u64 align(8) = 0;
    const ret = syscall.futex_wait(@ptrCast(&val), 0, 0);
    t.expectEqual("§3.2.2", E_TIMEOUT, ret);
    syscall.shutdown();
}
