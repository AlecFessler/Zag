const lib = @import("lib");

const perms = lib.perms;
const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.7.4 — Process retains SHM handle after `shm_unmap`.
pub fn main(pv: u64) void {
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_ret = syscall.shm_create_with_rights(4096, shm_rights.bits());
    const shm_handle: u64 = @bitCast(shm_ret);
    _ = syscall.shm_map(shm_handle, vm_handle, 0);
    _ = syscall.shm_unmap(shm_handle, vm_handle);
    // Verify handle still exists in user view.
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == shm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            found = true;
            break;
        }
    }
    if (found) {
        t.pass("§4.7.4");
    } else {
        t.fail("§4.7.4");
    }
    syscall.shutdown();
}
