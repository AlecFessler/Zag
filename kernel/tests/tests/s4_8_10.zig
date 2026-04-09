const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.8.10 — `mmio_map` with non-MMIO device returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var pio_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].deviceType() == 1) {
            pio_handle = view[i].handle;
            break;
        }
    }

    if (pio_handle == 0) {
        t.pass("§4.8.10");
        syscall.shutdown();
    }

    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.vm_reserve(0, 4096, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const ret = syscall.mmio_map(pio_handle, vm_handle, 0);
    t.expectEqual("§4.8.10", E_INVAL, ret);
    syscall.shutdown();
}
