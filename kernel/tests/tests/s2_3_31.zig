const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.3.31 — `mem_shm_map` with invalid `vm_handle` returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    const ret = syscall.mem_shm_map(shm_handle, 99999, 0);
    t.expectEqual("§2.3.31", E_BADHANDLE, ret);
    syscall.shutdown();
}
