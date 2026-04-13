const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.56 — `mem_unmap` with size=0 returns `E_INVAL`.
pub fn main(pv: u64) void {
    _ = pv;

    const rights = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.mem_reserve(0, 4096, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    // size=0 is invalid.
    const ret = syscall.mem_unmap(vm_handle, 0, 0);
    t.expectEqual("§2.3.56", E_INVAL, ret);
    syscall.shutdown();
}
