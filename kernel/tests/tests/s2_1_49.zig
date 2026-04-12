const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.1.49 — `restart` can only be granted by a parent that itself has restart capability.
pub fn main(_: u64) void {
    // Root service starts with restart capability. Disable it first.
    _ = syscall.disable_restart();

    // Now try creating a child with restart — should fail with E_PERM.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .restart = true };
    const ret = syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits());
    t.expectEqual("§2.1.49", E_PERM, ret);
    syscall.shutdown();
}
