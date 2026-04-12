const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.50 — `mem_mmio_map` with duplicate device region returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.3.50");
    const dev_handle = dev.handle;
    const dev_size: u32 = dev.deviceSizeOrPortCount();

    const page_size: u64 = 4096;
    const size = ((@as(u64, dev_size) + page_size - 1) / page_size) * page_size;
    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };

    // Create reservation big enough for two mappings.
    const vm1 = syscall.mem_reserve(0, size * 2, rights.bits());
    const vm_handle1: u64 = @bitCast(vm1.val);

    // First map at offset 0 should succeed.
    _ = syscall.mem_mmio_map(dev_handle, vm_handle1, 0);

    // Second map of same device in same reservation should fail with E_INVAL.
    const ret = syscall.mem_mmio_map(dev_handle, vm_handle1, size);
    t.expectEqual("§2.3.50", E_INVAL, ret);
    syscall.shutdown();
}
