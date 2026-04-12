const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.2.8 — `getrandom` with `len > 4096` returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var buf: [8]u8 = undefined;
    const rc = syscall.getrandom(&buf, 4097);
    t.expectEqual("§5.2.8", syscall.E_INVAL, rc);
    syscall.shutdown();
}
