const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;

/// §2.2.10 — After `mmio_unmap`, the range reverts to private with max RWX
/// rights. We reserve the region with read+write+execute (plus mmio so we
/// can mmio_map it in the first place), map MMIO, unmap, then verify that
/// every page of the range is writable AND readable as fresh private memory.
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
    if (dev_handle == 0) {
        t.fail("§2.2.10");
        syscall.shutdown();
    }

    // Reserve at least one page, rounded to page size.
    const size: u64 = @max(PAGE, @as(u64, dev_size + 4095) & ~@as(u64, 4095));
    const vm_rights = perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .mmio = true,
    };
    const vm = syscall.vm_reserve(0, size, vm_rights.bits());
    const vm_h: u64 = @bitCast(vm.val);

    // Map and unmap the MMIO region.
    if (syscall.mmio_map(dev_handle, vm_h, 0) != 0) {
        t.fail("§2.2.10");
        syscall.shutdown();
    }
    if (syscall.mmio_unmap(dev_handle, vm_h) != 0) {
        t.fail("§2.2.10");
        syscall.shutdown();
    }

    // Post-unmap: every page must be writable+readable as fresh private
    // memory. If the reservation did not revert to max RWX, writes would
    // fault on non-writable pages.
    const base = vm.val2;
    const n_pages = size / PAGE;
    var i: u64 = 0;
    while (i < n_pages) : (i += 1) {
        const ptr: *volatile u64 = @ptrFromInt(base + i * PAGE);
        const magic: u64 = 0xBADB_0000 + i;
        ptr.* = magic;
        if (ptr.* != magic) {
            t.fail("§2.2.10");
            syscall.shutdown();
        }
    }

    t.pass("§2.2.10");
    syscall.shutdown();
}
