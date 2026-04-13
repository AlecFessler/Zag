const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.44 — `mem_unmap` with zero `size` returns `E_INVAL`.
pub fn main(pv: u64) void {
    _ = pv;

    const rights = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.mem_reserve(0, 4096, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    // size=0 is invalid.
    const ret = syscall.mem_unmap(vm_handle, 0, 0);
    t.expectEqual("§2.3.44", E_INVAL, ret);
    syscall.shutdown();
}
