const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.10.4 — `proc_create` with `restart` in perms without parent restart capability returns `E_PERM`.
pub fn main(_: u64) void {
    _ = syscall.disable_restart();
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .restart = true };
    const ret = syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits());
    t.expectEqual("§4.10.4", E_PERM, ret);
    syscall.shutdown();
}
