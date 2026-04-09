const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.3.4 — Once cleared via `disable_restart`, the restart capability cannot be re-enabled.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Root service has restart. Disable it.
    _ = syscall.disable_restart();
    // Now try to create a child with restart — should fail because we no longer have restart.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .restart = true };
    const ret = syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits());
    // Also verify calling disable_restart again returns E_PERM (already cleared).
    const ret2 = syscall.disable_restart();
    if (ret == E_PERM and ret2 == E_PERM) {
        t.pass("§2.3.4");
    } else {
        t.fail("§2.3.4");
    }
    syscall.shutdown();
}
