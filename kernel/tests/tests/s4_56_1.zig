const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.56.1 — `clock_getwall` returns a positive i64 representing nanoseconds since the Unix epoch.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ns = syscall.clock_getwall();
    if (ns > 0) {
        t.pass("§4.56.1");
    } else {
        t.failWithVal("§4.56.1", 1, ns);
    }
    syscall.shutdown();
}
