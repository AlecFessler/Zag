const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.1.96 — `revoke_perm` on `HANDLE_SELF` returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.revoke_perm(0);
    t.expectEqual("§2.1.96", E_INVAL, ret);
    syscall.shutdown();
}
