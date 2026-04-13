const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.3.35 — `mem_shm_map` without `shareable` right on reservation returns `E_PERM`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Reservation without shareable.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.mem_reserve(0, 4096, rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    const ret = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    t.expectEqual("§2.3.35", E_PERM, ret);
    syscall.shutdown();
}
