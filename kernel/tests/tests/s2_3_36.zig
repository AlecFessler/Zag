const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.3.36 — `mem_shm_map` with SHM RWX exceeding reservation max returns `E_PERM`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Reservation with read+shareable only.
    const ro_shareable = perms.VmReservationRights{ .read = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, ro_shareable.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    // SHM with read+write — write exceeds reservation max.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    const ret = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    t.expectEqual("§2.3.36", E_PERM, ret);
    syscall.shutdown();
}
