const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

/// §2.3.56 — `mem_mmio_unmap` when MMIO is not mapped returns `E_NOENT`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.3.56");
    const dev_handle = dev.handle;
    const dev_size: u32 = dev.deviceSizeOrPortCount();

    const page_size: u64 = 4096;
    const size = ((@as(u64, dev_size) + page_size - 1) / page_size) * page_size;
    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.mem_reserve(0, size, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    // Don't map, just try to unmap.
    const ret = syscall.mem_mmio_unmap(dev_handle, vm_handle);
    t.expectEqual("§2.3.56", E_NOENT, ret);
    syscall.shutdown();
}
