const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.3.43 — `mem_mmio_map` with invalid `device_handle` returns `E_BADHANDLE`.
pub fn main(pv: u64) void {
    _ = pv;
    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.mem_reserve(0, 4096, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const ret = syscall.mem_mmio_map(0xFFFFFFFF, vm_handle, 0);
    t.expectEqual("§2.3.43", E_BADHANDLE, ret);
    syscall.shutdown();
}
