const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.6.7 — `shm_map` with out-of-bounds range returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Reservation is 4096 bytes, SHM is 4096 bytes, offset 4096 would go out of bounds.
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    const ret = syscall.shm_map(shm_handle, vm_handle, 4096);
    t.expectEqual("§4.6.7", E_INVAL, ret);
    syscall.shutdown();
}
