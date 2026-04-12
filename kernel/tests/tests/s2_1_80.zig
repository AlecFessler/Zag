const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.80 — `proc_create` returns handle ID (positive) on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true };
    const ret = syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits());
    if (ret > 0) {
        t.pass("§2.1.80");
    } else {
        t.failWithVal("§2.1.80", 1, ret);
    }
    syscall.shutdown();
}
