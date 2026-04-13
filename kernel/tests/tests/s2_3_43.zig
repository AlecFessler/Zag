const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.43 — `mem_unmap` with non-page-aligned `offset` returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.mem_reserve(0, 4096, rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    // Non-page-aligned offset.
    const ret = syscall.mem_unmap(vm_handle, 1, 4096);
    t.expectEqual("§2.3.43", E_INVAL, ret);
    syscall.shutdown();
}
