const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.1.7 — `clock_getwall` returns a positive i64 representing nanoseconds since the Unix epoch.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ns = syscall.clock_getwall();
    if (ns > 0) {
        t.pass("§5.1.7");
    } else {
        t.failWithVal("§5.1.7", 1, ns);
    }
    syscall.shutdown();
}
