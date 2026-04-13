const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.40 — `mem_unmap` with invalid offset/size returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    // Unmap beyond reservation bounds — should fail with E_INVAL.
    const ret = syscall.mem_unmap(vm_handle, 0, 8192);
    t.expectEqual("§2.3.40", E_INVAL, ret);
    syscall.shutdown();
}
