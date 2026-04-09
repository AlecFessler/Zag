const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.4 — `shm_map` maps the full SHM region at the specified offset.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Map SHM at offset 4096 in an 8192-byte reservation.
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 8192, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    _ = syscall.shm_map(shm_handle, vm_handle, 4096);
    // Write to the SHM via the mapped offset.
    const ptr: *volatile u64 = @ptrFromInt(vm.val2 + 4096);
    ptr.* = 0xCAFEBABE;
    if (ptr.* == 0xCAFEBABE) {
        t.pass("§2.2.4");
    } else {
        t.fail("§2.2.4");
    }
    syscall.shutdown();
}
