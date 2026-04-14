const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_TIMEOUT: i64 = -8;

/// §3.2.10 — `futex_wait_val` returns `E_TIMEOUT` on timeout expiry.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var val: u64 = 0;
    // Test 1: timeout=0 means try-only, returns E_TIMEOUT immediately.
    const ret0 = syscall.futex_wait(&val, 0, 0);
    if (ret0 != E_TIMEOUT) {
        t.failWithVal("§3.2.10", E_TIMEOUT, ret0);
        syscall.shutdown();
    }
    // Test 2: small non-zero timeout — thread actually blocks, then times out.
    const before = syscall.clock_gettime();
    const ret1 = syscall.futex_wait(&val, 0, 1_000_000); // 1ms
    const after = syscall.clock_gettime();
    if (ret1 != E_TIMEOUT) {
        t.failWithVal("§3.2.10", E_TIMEOUT, ret1);
        syscall.shutdown();
    }
    // Verify some time actually passed (at least ~500us to account for timer granularity).
    if (after - before >= 500_000) {
        t.pass("§3.2.10");
    } else {
        t.fail("§3.2.10");
    }
    syscall.shutdown();
}
