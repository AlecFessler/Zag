const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.3.54 — `mem_mmio_map` without `mmio` right on reservation returns `E_PERM`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.3.54");
    const dev_handle = dev.handle;

    // Create reservation with read+write but WITHOUT mmio right.
    const rights = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.mem_reserve(0, 4096, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const ret = syscall.mem_mmio_map(dev_handle, vm_handle, 0);
    t.expectEqual("§2.3.54", E_PERM, ret);
    syscall.shutdown();
}
