const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.2 — Pages demand-paged after unmap are guaranteed to be zeroed.
///
/// We map an SHM region, write non-zero data, unmap, then read the same VA.
/// The demand-paged page must be all zeroes.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const vaddr: u64 = vm.val2;

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);

    // Write non-zero data through the SHM mapping.
    const buf: [*]volatile u8 = @ptrFromInt(vaddr);
    for (0..4096) |i| buf[i] = 0xAA;

    // Unmap the SHM.
    _ = syscall.mem_unmap(vm_handle, 0, 4096);

    // After unmap, the demand-paged page must be zeroed.
    var all_zero = true;
    for (0..4096) |i| {
        if (buf[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        t.pass("§2.3.2");
    } else {
        t.fail("§2.3.2");
    }
    syscall.shutdown();
}
