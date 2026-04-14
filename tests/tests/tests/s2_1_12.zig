const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.12 — If device handle return reaches root with no valid destination, the handle is dropped.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.1.12");
    const dev_handle = dev.handle;
    const dev_field0 = dev.field0;

    // Spawn child that will hold the device and exit.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_recv_device_exit.ptr), children.child_recv_device_exit.len, child_rights.bits())));

    // Fill our own perm table BEFORE transferring device so the table is full
    // when the device return happens. Device transfer is exclusive (frees our slot),
    // so fill after transfer to reclaim that slot.
    const fill_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        const r = syscall.mem_reserve(0, 4096, fill_rights);
        if (r.val < 0) break;
    }

    // Transfer device to child. This frees our device slot (exclusive transfer).
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // Fill the slot freed by device transfer.
    _ = syscall.mem_reserve(0, 4096, fill_rights);

    // Child exits after reply — device tries to return to root, but root table is full.
    // Device should be dropped (§2.1.12).

    // Wait for child to die.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        var child_dead = false;
        for (0..128) |j| {
            if (view[j].handle == ch and view[j].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
                child_dead = true;
                break;
            }
        }
        if (child_dead) break;
        syscall.thread_yield();
    }

    // Verify device did NOT return (was dropped).
    var device_found = false;
    for (0..128) |j| {
        if (view[j].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[j].field0 == dev_field0) {
            device_found = true;
            break;
        }
    }

    if (!device_found) {
        t.pass("§2.1.12");
    } else {
        t.fail("§2.1.12");
    }
    syscall.shutdown();
}
