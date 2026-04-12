const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.56.3 — `clock_getwall` always succeeds.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Call clock_getwall multiple times — every call should return a
    // positive value (success), never a negative error code.
    var all_ok = true;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const ns = syscall.clock_getwall();
        if (ns <= 0) {
            all_ok = false;
            break;
        }
    }
    if (all_ok) {
        t.pass("§4.56.3");
    } else {
        t.fail("§4.56.3");
    }
    syscall.shutdown();
}
