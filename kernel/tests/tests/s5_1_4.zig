const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.1.4 — `clock_getwall` precision is limited by the underlying monotonic clock source (TSC on x86).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Two successive calls should return monotonically non-decreasing values,
    // confirming the wall clock tracks the monotonic source.
    const t1 = syscall.clock_getwall();
    const t2 = syscall.clock_getwall();
    if (t2 >= t1 and t1 > 0) {
        t.pass("§5.1.4");
    } else {
        t.fail("§5.1.4");
    }
    syscall.shutdown();
}
