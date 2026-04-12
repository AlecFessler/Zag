const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.28 — `mem_perms` on a range containing SHM or MMIO nodes returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Create shareable reservation with RW.
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    // Create SHM with RW (no execute, so it fits within reservation max).
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    // Try mem_perms on the range with SHM mapped.
    const ro = perms.VmReservationRights{ .read = true };
    const ret = syscall.mem_perms(vm_handle, 0, 4096, ro.bits());
    t.expectEqual("§2.3.28", E_INVAL, ret);
    syscall.shutdown();
}
