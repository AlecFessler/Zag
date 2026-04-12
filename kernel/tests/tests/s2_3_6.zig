const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.6 — After `mem_shm_unmap`, the range reverts to private with max RWX rights.
///
/// We reserve the range with read+write+execute so that "max RWX" means all
/// three bits are observable post-unmap. After unmapping, we verify:
///   - Read: fresh demand-paged page reads as zero (not the old SHM value).
///   - Write: a new value written sticks.
///   - Execute: we write a single `ret` (0xC3) into the page and invoke it
///     via a function pointer. If execute rights did not revert with the
///     page, this would take a #PF(xd) and crash the test.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rwx = perms.VmReservationRights{ .read = true, .write = true, .execute = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rwx.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    // Write a known pattern to SHM.
    const ptr: *volatile u64 = @ptrFromInt(vm.val2);
    ptr.* = 0xDEAD_BEEF_CAFE_BABE;
    // Unmap SHM.
    _ = syscall.mem_shm_unmap(shm_handle, vm_handle);
    // After unmap, range reverts to private demand-paged. Reading should yield zero
    // (fresh demand-paged page), NOT the old SHM data.
    const read_val = ptr.*;
    if (read_val != 0) {
        t.failWithVal("§2.3.6", 0, @bitCast(read_val));
        syscall.shutdown();
    }
    // Write a fresh value and verify it sticks (write right present).
    ptr.* = 0x1234_5678_9ABC_DEF0;
    if (ptr.* != 0x1234_5678_9ABC_DEF0) {
        t.fail("§2.3.6");
        syscall.shutdown();
    }
    // Execute right: write a single RET (0xC3) and invoke via fn pointer.
    // If execute rights failed to revert, this faults with invalid_execute.
    const code_ptr: *volatile u8 = @ptrFromInt(vm.val2);
    code_ptr.* = 0xC3;
    const func: *const fn () void = @ptrFromInt(vm.val2);
    func();
    t.pass("§2.3.6");
    syscall.shutdown();
}
