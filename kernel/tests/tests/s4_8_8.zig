const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.8.8 — `mmio_map` with out-of-bounds range returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var dev_handle: u64 = 0;
    var dev_size: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].deviceType() == 0) {
            dev_handle = view[i].handle;
            dev_size = view[i].deviceSizeOrPortCount();
            break;
        }
    }

    // Reserve only one page — smaller than most MMIO devices, or use offset
    // that pushes the mapping beyond the reservation.
    const page_size: u64 = 4096;
    const size = ((@as(u64, dev_size) + page_size - 1) / page_size) * page_size;
    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.vm_reserve(0, size, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    // Offset beyond reservation: device mapped at offset=size would exceed bounds.
    const ret = syscall.mmio_map(dev_handle, vm_handle, size);
    t.expectEqual("§4.8.8", E_INVAL, ret);
    syscall.shutdown();
}
