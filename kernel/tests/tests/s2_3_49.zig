const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.49 — The process retains the VM reservation handle after `mem_unmap` — only `revoke_perm` performs full reservation teardown.
///
/// We reserve a region, map SHM, unmap, then verify the VM reservation handle
/// is still present in the permission view. After that, we verify we can still
/// use the handle (e.g., map SHM again).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);

    // Unmap the SHM.
    if (syscall.mem_unmap(vm_handle, 0, 4096) != 0) {
        t.fail("§2.3.49 unmap");
        syscall.shutdown();
    }

    // Verify the VM reservation handle is still in the permission view.
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == vm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_VM_RESERVATION) {
            found = true;
            break;
        }
    }
    if (!found) {
        t.fail("§2.3.49 handle gone");
        syscall.shutdown();
    }

    // Verify the handle is still usable — re-map the SHM.
    const ret = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    if (ret != 0) {
        t.fail("§2.3.49 re-map failed");
        syscall.shutdown();
    }

    t.pass("§2.3.49");
    syscall.shutdown();
}
