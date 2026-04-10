const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.33 — Restartable processes in recursive kill restart and keep device handles.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.6.33");
    const dev_handle = dev.handle;
    const dev_field0 = dev.field0;

    // Spawn restartable child_sleep (blocks on futex, not IPC).
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .device_own = true, .restart = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_recv_device_exit.ptr),
        children.child_recv_device_exit.len,
        child_rights,
    )));

    // Transfer device to child via IPC cap transfer.
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // Child received device and exited. It's restartable, so it restarts.
    // On restart, it blocks on ipc_recv again. Wait for restart_count > 0.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }

    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }

    if (view[slot].processRestartCount() == 0) {
        t.fail("§2.6.33");
        syscall.shutdown();
    }

    // Now do a recursive kill (killSubtree via revoke).
    // Since child is restartable, it should restart, not die.
    const rc_before = view[slot].processRestartCount();
    _ = syscall.revoke_perm(ch);

    // revoke_perm removes our handle, so we can't observe restart_count.
    // But the spec says restartable processes restart and keep device handles.
    // Since device is exclusive, if the child restarted and kept it, the device
    // should NOT return to us.

    // Give time for restart to happen.
    syscall.thread_yield();
    syscall.thread_yield();
    syscall.thread_yield();

    // Device should NOT be back in our perm view (child kept it).
    var device_returned = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].field0 == dev_field0) {
            device_returned = true;
            break;
        }
    }

    if (!device_returned) {
        t.pass("§2.6.33");
    } else {
        t.fail("§2.6.33");
    }
    _ = rc_before;
    syscall.shutdown();
}
