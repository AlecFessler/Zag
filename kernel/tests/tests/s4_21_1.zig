const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.21.1 — `disable_restart` returns `E_OK` on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.disable_restart();
    if (ret != 0) {
        t.fail("§4.21.1");
        syscall.shutdown();
    }

    // Verify restart is actually disabled: proc_create with restart should fail with E_PERM.
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .restart = true }).bits();
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_exit.ptr),
        children.child_exit.len,
        child_rights,
    );
    if (child_ret == -2) {
        t.pass("§4.21.1");
    } else {
        t.fail("§4.21.1");
    }
    syscall.shutdown();
}
