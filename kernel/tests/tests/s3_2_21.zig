const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var futex_val: u64 align(8) = 0;

/// §3.2.21 — `futex_wait_change` has the same timeout semantics as `futex_wait_val`: `0` is non-blocking, `MAX_U64` is indefinite, finite blocks for at least that duration.
pub fn main(_: u64) void {
    var addrs = [1]u64{@intFromPtr(&futex_val)};
    // Test 1: timeout=0 is non-blocking, returns E_TIMEOUT immediately.
    const ret0 = syscall.futex_wait_change(@intFromPtr(&addrs), 1, 0);
    if (ret0 != syscall.E_TIMEOUT) {
        t.failWithVal("§3.2.21", syscall.E_TIMEOUT, ret0);
        syscall.shutdown();
    }
    // Test 2: finite timeout blocks for at least that duration.
    const timeout_ns: u64 = 10_000_000; // 10ms
    const before = syscall.clock_gettime();
    const ret1 = syscall.futex_wait_change(@intFromPtr(&addrs), 1, timeout_ns);
    const after = syscall.clock_gettime();
    const elapsed: u64 = @bitCast(after - before);
    if (ret1 != syscall.E_TIMEOUT) {
        t.failWithVal("§3.2.21", syscall.E_TIMEOUT, ret1);
        syscall.shutdown();
    }
    if (elapsed >= timeout_ns) {
        t.pass("§3.2.21");
    } else {
        t.fail("§3.2.21");
    }
    syscall.shutdown();
}
