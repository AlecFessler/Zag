const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

/// §2.3.40 — `mem_shm_unmap` when SHM is not mapped returns `E_NOENT`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    // Never mapped — unmap should fail.
    const ret = syscall.mem_shm_unmap(shm_handle, vm_handle);
    t.expectEqual("§2.3.40", E_NOENT, ret);
    syscall.shutdown();
}
