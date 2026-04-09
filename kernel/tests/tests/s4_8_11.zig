const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_EXIST: i64 = -12;

/// §4.8.11 — `mmio_map` with committed pages in range returns `E_EXIST`.
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
    const vm = syscall.vm_reserve(0, size, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    // Touch the first page to commit it via demand-paging.
    const ptr: *volatile u8 = @ptrFromInt(vm.val2);
    ptr.* = 42;

    // Now mmio_map should fail because the page is already committed.
    const ret = syscall.mmio_map(dev_handle, vm_handle, 0);
    t.expectEqual("§4.8.11", E_EXIST, ret);
    syscall.shutdown();
}
