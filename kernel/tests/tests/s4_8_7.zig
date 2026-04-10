const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.8.7 — `mmio_map` with non-page-aligned offset returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§4.8.7");
    const dev_handle = dev.handle;

    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.vm_reserve(0, 8192, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const ret = syscall.mmio_map(dev_handle, vm_handle, 1);
    t.expectEqual("§4.8.7", E_INVAL, ret);
    syscall.shutdown();
}
