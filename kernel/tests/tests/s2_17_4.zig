const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.17.4 — Requests with zero length return `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var buf: [8]u8 = undefined;
    const rc = syscall.getrandom(&buf, 0);
    t.expectEqual("§2.17.4", syscall.E_INVAL, rc);
    syscall.shutdown();
}
