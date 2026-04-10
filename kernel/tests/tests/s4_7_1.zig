const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.7.1 — `shm_unmap` returns `E_OK` on success.
///
/// After unmap, the page must become zero-filled demand-paged private memory
/// per §2.2.7. We write a pattern through the SHM mapping, unmap, then touch
/// the same VA and confirm it reads back as zero.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const vaddr: u64 = vm.val2;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    _ = syscall.shm_map(shm_handle, vm_handle, 0);

    // Stamp a non-zero pattern through the SHM.
    const buf: [*]volatile u8 = @ptrFromInt(vaddr);
    for (0..64) |i| buf[i] = 0xCC;

    const ret = syscall.shm_unmap(shm_handle, vm_handle);
    t.expectEqual("§4.7.1", 0, ret);

    // Touching the page now should fault-in zeroed private memory.
    for (0..64) |i| {
        if (buf[i] != 0) {
            t.fail("§4.7.1 page not zero-filled after unmap");
            syscall.shutdown();
        }
    }
    t.pass("§4.7.1 post-unmap page zero-filled");
    syscall.shutdown();
}
