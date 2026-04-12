const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.17.3 — The maximum buffer size per call is 4096 bytes.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var buf: [8]u8 = undefined;
    // Request more than 4096 bytes — should return E_INVAL.
    const rc = syscall.getrandom(&buf, 4097);
    t.expectEqual("§2.17.3", syscall.E_INVAL, rc);
    syscall.shutdown();
}
