const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.1.48 — Handle 0 (`HANDLE_SELF`) exists at process creation and cannot be revoked.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Verify handle 0 exists.
    const exists = view[0].handle == 0 and view[0].entry_type == perm_view.ENTRY_TYPE_PROCESS;
    // Attempt to revoke handle 0 — should return E_INVAL.
    const revoke_ret = syscall.revoke_perm(0);
    if (exists and revoke_ret == E_INVAL) {
        t.pass("§2.1.48");
    } else {
        t.fail("§2.1.48");
    }
    syscall.shutdown();
}
