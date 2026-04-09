const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.7 — After `shm_unmap`, the range reverts to private with max RWX rights.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rwx = perms.VmReservationRights{ .read = true, .write = true, .execute = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, shareable_rwx.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    _ = syscall.shm_map(shm_handle, vm_handle, 0);
    // Write a known pattern to SHM.
    const ptr: *volatile u64 = @ptrFromInt(vm.val2);
    ptr.* = 0xDEAD_BEEF_CAFE_BABE;
    // Unmap SHM.
    _ = syscall.shm_unmap(shm_handle, vm_handle);
    // After unmap, range reverts to private demand-paged. Reading should yield zero
    // (fresh demand-paged page), NOT the old SHM data.
    const val = ptr.*;
    if (val == 0) {
        t.pass("§2.2.7");
    } else {
        // If we read back the old SHM data, the unmap didn't properly revert to private.
        t.failWithVal("§2.2.7", 0, @bitCast(val));
    }
    syscall.shutdown();
}
