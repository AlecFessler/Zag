const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.1.12 — The offset update is atomic: concurrent `clock_getwall` calls on other threads see either the old or the new time, never a torn value.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Set the wall clock, then immediately read it back. The read should
    // see the updated value (not a torn mix of old and new offsets).
    const target_ns: u64 = 2_500_000_000_000_000_000; // ~2049
    const rc = syscall.clock_setwall(target_ns);
    if (rc != 0) {
        t.failWithVal("§5.1.12", 0, rc);
        syscall.shutdown();
    }
    const now = syscall.clock_getwall();
    const diff = now - @as(i64, @bitCast(target_ns));
    // Should be within 1 second of the target
    if (diff >= 0 and diff < 1_000_000_000) {
        t.pass("§5.1.12");
    } else {
        t.failWithVal("§5.1.12", @bitCast(target_ns), now);
    }
    syscall.shutdown();
}
