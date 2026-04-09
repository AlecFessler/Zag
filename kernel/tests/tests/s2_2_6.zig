const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.6 — `shm_unmap` removes the SHM mapping from the reservation.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    _ = syscall.shm_map(shm_handle, vm_handle, 0);
    // Unmap should succeed.
    const unmap_ret = syscall.shm_unmap(shm_handle, vm_handle);
    // Re-mapping at the same offset should now succeed (mapping was removed).
    const remap_ret = syscall.shm_map(shm_handle, vm_handle, 0);
    if (unmap_ret == 0 and remap_ret == 0) {
        t.pass("§2.2.6");
    } else {
        t.fail("§2.2.6");
    }
    syscall.shutdown();
}
