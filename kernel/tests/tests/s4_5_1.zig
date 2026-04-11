const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.5.1 — `mem_shm_create` returns handle ID (positive) on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const ret = syscall.shm_create_with_rights(4096, rights.bits());
    if (ret > 0) {
        t.pass("§4.5.1");
    } else {
        t.failWithVal("§4.5.1", 1, ret);
    }
    syscall.shutdown();
}
