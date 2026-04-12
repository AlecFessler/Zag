const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.16.1 — `clock_getwall` returns nanoseconds since the Unix epoch (1970-01-01T00:00:00Z).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ns = syscall.clock_getwall();
    // A reasonable wall clock value should be positive and represent a time
    // after 2020-01-01 (~1577836800 seconds = ~1577836800000000000 ns).
    const min_ns: i64 = 1_577_836_800_000_000_000;
    if (ns > min_ns) {
        t.pass("§2.16.1");
    } else {
        t.failWithVal("§2.16.1", min_ns, ns);
    }
    syscall.shutdown();
}
