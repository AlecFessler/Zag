const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

fn waitForDeath(view: [*]const perm_view.UserViewEntry, handle: u64) perm_view.CrashReason {
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == handle) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 1_000_000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    return view[slot].processCrashReason();
}

fn findPioDevice(view: [*]const perm_view.UserViewEntry) u64 {
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].deviceType() == 1) {
            return view[i].handle;
        }
    }
    return 0;
}

/// §2.5.8 — Virtual BAR access with a non-MOV instruction kills the process with `protection_fault`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    _ = t.requirePioDevice(view, "§2.5.8");
    const dev_handle = findPioDevice(view);
    if (dev_handle == 0) {
        t.fail("§2.5.8 no_pio_device");
        syscall.shutdown();
    }

    // Spawn child with mem_reserve + device_own rights.
    const child_rights = (perms.ProcessRights{ .mem_reserve = true, .device_own = true }).bits();
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_vbar_non_mov.ptr),
        children.child_vbar_non_mov.len,
        child_rights,
    );
    if (child_ret < 0) {
        t.failWithVal("§2.5.8 proc_create", 0, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(@as(i64, child_ret));

    // Transfer the PIO device to the child via cap transfer.
    const dev_rights = (perms.DeviceRegionRights{ .map = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ dev_handle, dev_rights }, &reply);

    // Wait for the child to die and check the crash reason.
    const reason = waitForDeath(view, child_handle);
    if (reason == .protection_fault) {
        t.pass("§2.5.8");
    } else {
        t.failWithVal("§2.5.8", @intFromEnum(perm_view.CrashReason.protection_fault), @intFromEnum(reason));
    }
    syscall.shutdown();
}
