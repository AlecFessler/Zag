const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.8.9 — `mmio_map` with duplicate device region returns `E_INVAL`.
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

    const page_size: u64 = 4096;
    const size = ((@as(u64, dev_size) + page_size - 1) / page_size) * page_size;
    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };

    // Create reservation big enough for two mappings.
    const vm1 = syscall.vm_reserve(0, size * 2, rights.bits());
    const vm_handle1: u64 = @bitCast(vm1.val);

    // First map at offset 0 should succeed.
    _ = syscall.mmio_map(dev_handle, vm_handle1, 0);

    // Second map of same device in same reservation should fail with E_INVAL.
    const ret = syscall.mmio_map(dev_handle, vm_handle1, size);
    t.expectEqual("§4.8.9", E_INVAL, ret);
    syscall.shutdown();
}
