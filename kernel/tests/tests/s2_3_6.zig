const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.6 — After `mem_unmap`, pages demand-paged into the unmapped range are guaranteed to be zeroed.
///
/// After writing a magic value via the SHM mapping and unmapping, reading the
/// same VA must no longer observe the SHM contents (the range reverts to
/// private demand-paged per §2.2.7, so the fresh page is zeroed per §2.2.2).
pub fn main(_: u64) void {
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));

    if (syscall.mem_shm_map(shm_handle, vm_handle, 0) != 0) {
        t.fail("§2.3.6");
        syscall.shutdown();
    }

    // Write a magic value into the SHM page via the mapping.
    const ptr: *volatile u64 = @ptrFromInt(vm.val2);
    ptr.* = 0xCAFED00D_F00DBABE;
    if (ptr.* != 0xCAFED00D_F00DBABE) {
        t.fail("§2.3.6");
        syscall.shutdown();
    }

    // Unmap the SHM — the VA must no longer reach the SHM backing page.
    if (syscall.mem_unmap(vm_handle, 0, 4096) != 0) {
        t.fail("§2.3.6");
        syscall.shutdown();
    }

    // Reading the same VA must NOT return the SHM contents. §2.2.7 says the
    // range reverts to private with max RWX; a fresh demand-paged page is
    // zero (§2.2.2). If unmap were a no-op the magic would still be visible.
    const post: u64 = ptr.*;
    if (post == 0xCAFED00D_F00DBABE) {
        t.fail("§2.3.6");
        syscall.shutdown();
    }

    // The SHM still exists and can be re-mapped elsewhere — verify it retains
    // the magic via a fresh reservation (proves the old VA no longer points
    // at the SHM physical page).
    const vm2 = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm2_h: u64 = @bitCast(vm2.val);
    if (syscall.mem_shm_map(shm_handle, vm2_h, 0) != 0) {
        t.fail("§2.3.6");
        syscall.shutdown();
    }
    const ptr2: *volatile u64 = @ptrFromInt(vm2.val2);
    if (ptr2.* != 0xCAFED00D_F00DBABE) {
        t.fail("§2.3.6");
        syscall.shutdown();
    }

    t.pass("§2.3.6");
    syscall.shutdown();
}
