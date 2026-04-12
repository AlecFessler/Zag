const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.36 — `mem_shm_map` with duplicate SHM in same reservation returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 8192, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    // First map succeeds.
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    // Second map of same SHM into same reservation should fail.
    const ret = syscall.mem_shm_map(shm_handle, vm_handle, 4096);
    t.expectEqual("§2.3.36", E_INVAL, ret);
    syscall.shutdown();
}
