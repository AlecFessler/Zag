const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.8.10 — `mem_mmio_map` with non-MMIO device returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const pio = t.requirePioDevice(view, "§4.8.10");
    const pio_handle = pio.handle;

    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.mem_reserve(0, 4096, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const ret = syscall.mem_mmio_map(pio_handle, vm_handle, 0);
    t.expectEqual("§4.8.10", E_INVAL, ret);
    syscall.shutdown();
}
