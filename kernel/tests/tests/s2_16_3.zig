const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.16.3 — `clock_setwall` atomically updates the wall clock offset so that subsequent `clock_getwall` calls reflect the new time.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Set the wall clock to a known value, then read it back.
    // The value should be close to what we set (within a reasonable margin
    // for elapsed time between set and get).
    const target_ns: u64 = 2_000_000_000_000_000_000; // ~2033
    const rc = syscall.clock_setwall(target_ns);
    if (rc != 0) {
        t.failWithVal("§2.16.3", 0, rc);
        syscall.shutdown();
    }
    const now = syscall.clock_getwall();
    // Allow 1 second of drift for execution time
    const diff = now - @as(i64, @bitCast(target_ns));
    if (diff >= 0 and diff < 1_000_000_000) {
        t.pass("§2.16.3");
    } else {
        t.failWithVal("§2.16.3", @bitCast(target_ns), now);
    }
    syscall.shutdown();
}
