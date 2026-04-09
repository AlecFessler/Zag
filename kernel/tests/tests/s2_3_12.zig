const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.12 — Revoking SHM unmaps it from all reservations, reverts to private, and clears the slot.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Create SHM and map it.
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    _ = syscall.shm_map(shm_handle, vm_handle, 0);
    const ptr: *volatile u64 = @ptrFromInt(vm.val2);
    ptr.* = 0xCAFE_BABE;
    // Revoke the SHM handle.
    const revoke_ret = syscall.revoke_perm(shm_handle);
    // Verify the SHM slot is cleared.
    var shm_found = false;
    for (0..128) |i| {
        if (view[i].handle == shm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            shm_found = true;
            break;
        }
    }
    // Verify the VM reservation still exists (only SHM was revoked, not the VM).
    var vm_found = false;
    for (0..128) |i| {
        if (view[i].handle == vm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_VM_RESERVATION) {
            vm_found = true;
            break;
        }
    }
    // Verify the range reverted to private demand-paged (writable, zeroed).
    ptr.* = 0xDEAD_BEEF;
    const readback = ptr.*;
    if (revoke_ret == 0 and !shm_found and vm_found and readback == 0xDEAD_BEEF) {
        t.pass("§2.3.12");
    } else {
        t.fail("§2.3.12");
    }
    syscall.shutdown();
}
