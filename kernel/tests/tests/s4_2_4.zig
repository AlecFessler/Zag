const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADADDR: i64 = -7;

/// §4.2.4 — `write` with invalid pointer returns `E_BADADDR`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.write_raw(0xFFFF_FFFF_FFFF_0000, 10);
    t.expectEqual("§4.2.4", E_BADADDR, ret);
    syscall.shutdown();
}
