const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.45 — `mem_unmap` with non-page-aligned `size` returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.mem_reserve(0, 4096, rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    // Non-page-aligned size.
    const ret = syscall.mem_unmap(vm_handle, 0, 100);
    t.expectEqual("§2.3.45", E_INVAL, ret);
    syscall.shutdown();
}
