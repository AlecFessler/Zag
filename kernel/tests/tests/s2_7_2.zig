const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.7.2 — SHM pages are zeroed on creation.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    const ptr: [*]const volatile u8 = @ptrFromInt(vm.val2);
    var all_zero = true;
    for (0..4096) |i| {
        if (ptr[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        t.pass("§2.7.2");
    } else {
        t.fail("§2.7.2");
    }
    syscall.shutdown();
}
