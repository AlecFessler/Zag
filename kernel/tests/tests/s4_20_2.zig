const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.20.2 — `revoke_perm` with invalid handle returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.revoke_perm(99999);
    t.expectEqual("§4.20.2", E_BADHANDLE, ret);
    syscall.shutdown();
}
