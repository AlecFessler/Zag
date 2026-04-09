const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.15.1 — `pin_exclusive` returns core_pin handle ID (positive) on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    _ = syscall.set_affinity(0b1);
    const ret = syscall.pin_exclusive();
    if (ret > 0) {
        t.pass("§4.15.1");
    } else {
        t.failWithVal("§4.15.1", 1, ret);
    }
    syscall.shutdown();
}
