const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.58.3 — `getrandom` with `len == 0` returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var buf: [8]u8 = undefined;
    const rc = syscall.getrandom(&buf, 0);
    t.expectEqual("§4.58.3", syscall.E_INVAL, rc);
    syscall.shutdown();
}
