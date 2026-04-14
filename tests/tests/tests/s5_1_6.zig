const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.1.6 — `clock_gettime` returns monotonic nanoseconds since boot.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const t1 = syscall.clock_gettime();
    // Burn some cycles to ensure measurable elapsed time.
    for (0..100) |_| syscall.thread_yield();
    const t2 = syscall.clock_gettime();

    // t1 > 0: we've been running since boot so time must be positive.
    // t2 > t1: monotonicity after burning cycles.
    // t2 - t1 < 10_000_000_000: elapsed < 10 seconds (sanity — 100 yields shouldn't take 10s).
    const elapsed = t2 - t1;
    if (t1 > 0 and t2 > t1 and elapsed < 10_000_000_000) {
        t.pass("§5.1.6");
    } else {
        t.fail("§5.1.6");
    }
    syscall.shutdown();
}
