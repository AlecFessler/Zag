const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_TIMEOUT: i64 = -8;

/// §3.2.4 — `futex_wait_val` with a finite timeout blocks for at least `timeout_ns` nanoseconds; actual expiry may be delayed until the next scheduler tick.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var val: u64 align(8) = 0;
    const timeout_ns: u64 = 10_000_000; // 10ms
    const before = syscall.clock_gettime();
    const ret = syscall.futex_wait(@ptrCast(&val), 0, timeout_ns);
    const after = syscall.clock_gettime();
    const elapsed: u64 = @bitCast(after - before);
    // Should return E_TIMEOUT, and elapsed should be >= timeout_ns.
    if (ret == E_TIMEOUT and elapsed >= timeout_ns) {
        t.pass("§3.2.4");
    } else {
        t.fail("§3.2.4");
    }
    syscall.shutdown();
}
