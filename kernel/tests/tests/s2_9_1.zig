const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.9.1 — Device access is exclusive (only one process holds the handle at a time).
/// After transferring a device to a child, the parent's handle must be gone, and a
/// second attempt to operate on it via the old handle must return E_BADHANDLE.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.9.1");
    const dev_handle = dev.handle;

    // Transfer device to child — exclusive, should disappear from our view.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_recv_device_exit.ptr), children.child_recv_device_exit.len, child_rights.bits())));
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // (a) The device must be gone from our user view.
    var still_here = false;
    for (0..128) |i| {
        if (view[i].handle == dev_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            still_here = true;
            break;
        }
    }
    if (still_here) {
        t.fail("§2.9.1 still_in_view");
        syscall.shutdown();
    }

    // (b) Access via the old handle must fail — the parent no longer owns it.
    const vm_rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.vm_reserve(0, 4096, vm_rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const E_BADHANDLE: i64 = -3;
    const rc = syscall.mmio_map(dev_handle, vm_handle, 0);
    if (rc == E_BADHANDLE) {
        t.pass("§2.9.1");
    } else {
        t.failWithVal("§2.9.1 after_transfer", E_BADHANDLE, rc);
    }
    syscall.shutdown();
}
