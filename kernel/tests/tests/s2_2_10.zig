const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.10 — After `mmio_unmap`, the range reverts to private with max RWX rights.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find an MMIO device.
    var dev_handle: u64 = 0;
    var dev_size: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].deviceType() == 0) {
            dev_handle = view[i].handle;
            dev_size = view[i].deviceSizeOrPortCount();
            break;
        }
    }

    // Create MMIO reservation.
    const size: u64 = @as(u64, dev_size + 4095) & ~@as(u64, 4095);
    const vm_rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.vm_reserve(0, size, vm_rights.bits());
    const vm_h: u64 = @bitCast(vm.val);

    // Map MMIO.
    _ = syscall.mmio_map(dev_handle, vm_h, 0);

    // Unmap MMIO.
    const unmap_ret = syscall.mmio_unmap(dev_handle, vm_h);
    if (unmap_ret != 0) {
        t.fail("§2.2.10");
        syscall.shutdown();
    }

    // After unmap, range reverts to private. Writing should work (demand-page a fresh page).
    const ptr: *volatile u64 = @ptrFromInt(vm.val2);
    ptr.* = 0x12345678;
    const val = ptr.*;
    if (val == 0x12345678) {
        t.pass("§2.2.10");
    } else {
        t.fail("§2.2.10");
    }
    syscall.shutdown();
}
