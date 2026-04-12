const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.1.7 — `mem_shm_create` returns handle ID (positive) on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const ret = syscall.shm_create_with_rights(4096, rights.bits());
    if (ret > 0) {
        t.pass("§3.1.7");
    } else {
        t.failWithVal("§3.1.7", 1, ret);
    }
    syscall.shutdown();
}
