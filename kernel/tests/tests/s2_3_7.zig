const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.7 — SHM, MMIO, and virtual BAR nodes must be fully contained within the `mem_unmap` range — partial overlap with any such node returns `E_INVAL`.
///
/// We map an SHM at offset 4096 within a 3-page reservation, then try to unmap
/// only the first 2 pages (offset 0, size 8192). The SHM at page 1 is fully
/// contained, so that should work. Then we re-map and try to unmap a range that
/// only partially overlaps the SHM — that must return E_INVAL.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 3 * 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    // Create a 2-page SHM to allow partial overlap testing.
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(2 * 4096, shm_rights.bits()));

    // Map the 2-page SHM at offset 4096 (pages 1-2 of the 3-page reservation).
    if (syscall.mem_shm_map(shm_handle, vm_handle, 4096) != 0) {
        t.fail("§2.3.7 setup shm_map");
        syscall.shutdown();
    }

    // Unmap only page 0 (offset 0, size 4096) — no SHM overlap, should succeed.
    const ret_private = syscall.mem_unmap(vm_handle, 0, 4096);
    if (ret_private != 0) {
        t.fail("§2.3.7 private-only unmap");
        syscall.shutdown();
    }

    // Try to unmap just page 1 (offset 4096, size 4096) — partial overlap with
    // the 2-page SHM node. Must return E_INVAL.
    const ret_partial = syscall.mem_unmap(vm_handle, 4096, 4096);
    t.expectEqual("§2.3.7", E_INVAL, ret_partial);
    syscall.shutdown();
}
