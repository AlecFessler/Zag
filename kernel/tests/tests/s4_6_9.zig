const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_EXIST: i64 = -12;

/// §4.6.9 — `shm_map` with committed pages in range returns `E_EXIST`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    // Touch the page to commit it via demand-paging.
    const ptr: *volatile u8 = @ptrFromInt(vm.val2);
    ptr.* = 42;
    // Now shm_map should fail because the page is committed.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    const ret = syscall.shm_map(shm_handle, vm_handle, 0);
    t.expectEqual("§4.6.9", E_EXIST, ret);
    syscall.shutdown();
}
