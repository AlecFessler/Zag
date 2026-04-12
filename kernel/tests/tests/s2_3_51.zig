const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §2.3.51 — `port_io` devices are valid targets for `mem_mmio_map`; the mapped size for `port_io` devices is `ceil(port_count / PAGE_SIZE) * PAGE_SIZE`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const pio = t.requirePioDevice(view, "§2.3.51");
    const pio_handle = pio.handle;

    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.mem_reserve(0, 4096, rights.bits());
    if (vm.val < 0) {
        t.failWithVal("§2.3.51 mem_reserve", 0, vm.val);
        syscall.shutdown();
    }
    const vm_handle: u64 = @bitCast(vm.val);

    const ret = syscall.mem_mmio_map(pio_handle, vm_handle, 0);
    t.expectEqual("§2.3.51", E_OK, ret);
    syscall.shutdown();
}
