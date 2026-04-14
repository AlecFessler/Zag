const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.47 — `mem_unmap` where the range partially overlaps an SHM, MMIO, or virtual BAR node returns `E_INVAL`.
///
/// We map a 1-page SHM at offset 0 within a 2-page reservation, then try to
/// unmap 2 pages starting at offset 0. Since the unmap range extends beyond the
/// SHM node into private territory, this is NOT partial overlap — the SHM is
/// fully contained. Instead, we map a 2-page SHM at offset 0, then try to unmap
/// only 1 page. That partially overlaps the SHM node and must return E_INVAL.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 3 * 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(2 * 4096, shm_rights.bits()));

    // Map the 2-page SHM at offset 0.
    if (syscall.mem_shm_map(shm_handle, vm_handle, 0) != 0) {
        t.fail("§2.3.47 setup");
        syscall.shutdown();
    }

    // Try to unmap only 1 page — partially overlaps the 2-page SHM.
    const ret = syscall.mem_unmap(vm_handle, 0, 4096);
    t.expectEqual("§2.3.47", E_INVAL, ret);
    syscall.shutdown();
}
