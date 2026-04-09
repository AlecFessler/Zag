const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.20.3 — `revoke_perm` on `HANDLE_SELF` returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.revoke_perm(0);
    t.expectEqual("§4.20.3", E_INVAL, ret);
    syscall.shutdown();
}
