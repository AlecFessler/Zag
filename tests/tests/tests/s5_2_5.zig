const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.2.5 — `getrandom` returns `E_OK` on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var buf: [32]u8 = undefined;
    const rc = syscall.getrandom(&buf, 32);
    t.expectEqual("§5.2.5", syscall.E_OK, rc);
    syscall.shutdown();
}
