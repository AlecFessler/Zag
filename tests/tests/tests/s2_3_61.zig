const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.61 — `mem_mmio_map` with `write_combining` reservation right on a `port_io` device returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const pio = t.requirePioDevice(view, "§2.3.61");
    const pio_handle = pio.handle;

    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true, .write_combining = true };
    const vm = syscall.mem_reserve(0, 4096, rights.bits());
    if (vm.val < 0) {
        t.failWithVal("§2.3.61 mem_reserve", 0, vm.val);
        syscall.shutdown();
    }
    const vm_handle: u64 = @bitCast(vm.val);

    const ret = syscall.mem_mmio_map(pio_handle, vm_handle, 0);
    t.expectEqual("§2.3.61", E_INVAL, ret);
    syscall.shutdown();
}
