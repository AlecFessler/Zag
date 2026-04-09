const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.11.29 — Device capability transfer requires the target to have `device_own`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a device handle in our perm_view.
    var dev_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = view[i].handle;
            break;
        }
    }

    // Spawn child_ipc_server WITHOUT device_own — child blocks on recv.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));

    // Give child time to start and block on recv.
    syscall.thread_yield();
    syscall.thread_yield();

    // Try to transfer device to child lacking device_own — should get E_PERM.
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    const rc = syscall.ipc_send_cap(ch, &.{ dev_handle, dev_rights });
    t.expectEqual("§2.11.29", E_PERM, rc);
    syscall.shutdown();
}
