const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §4.9.1 — `mem_mmio_unmap` returns `E_OK` on success.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§4.9.1");
    const dev_handle = dev.handle;
    const dev_size: u32 = dev.deviceSizeOrPortCount();

    const page_size: u64 = 4096;
    const size = ((@as(u64, dev_size) + page_size - 1) / page_size) * page_size;
    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.mem_reserve(0, size, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    _ = syscall.mem_mmio_map(dev_handle, vm_handle, 0);
    const ret = syscall.mem_mmio_unmap(dev_handle, vm_handle);
    t.expectEqual("§4.9.1", E_OK, ret);
    syscall.shutdown();
}
