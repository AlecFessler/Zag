const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.8.8 — `mem_mmio_map` with out-of-bounds range returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§4.8.8");
    const dev_handle = dev.handle;
    const dev_size: u32 = dev.deviceSizeOrPortCount();

    // Reserve only one page — smaller than most MMIO devices, or use offset
    // that pushes the mapping beyond the reservation.
    const page_size: u64 = 4096;
    const size = ((@as(u64, dev_size) + page_size - 1) / page_size) * page_size;
    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.mem_reserve(0, size, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    // Offset beyond reservation: device mapped at offset=size would exceed bounds.
    const ret = syscall.mem_mmio_map(dev_handle, vm_handle, size);
    t.expectEqual("§4.8.8", E_INVAL, ret);
    syscall.shutdown();
}
