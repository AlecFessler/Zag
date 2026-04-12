const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.3.33 — `send` cap transfer without appropriate `send_shm`/`send_process`/`send_device` right returns `E_PERM`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child_send_self_then_recv — it will send HANDLE_SELF with limited rights
    // (send_words + grant only, NO send_shm/send_process/send_device).
    const child_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_then_recv.ptr),
        children.child_send_self_then_recv.len,
        child_rights,
    )));

    // Call child — it replies with HANDLE_SELF via cap transfer (limited rights)
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    // Find the limited handle (different from ch, process type)
    var limited_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].handle != 0 and view[i].handle != ch and
            view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS)
        {
            limited_handle = view[i].handle;
            break;
        }
    }
    if (limited_handle == 0) {
        t.fail("§3.3.33 setup");
        syscall.shutdown();
    }

    // Child is now blocking on recv (second recv in child_send_self_then_recv).
    // Create SHM to attempt cap transfer.
    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true, .grant = true }).bits();
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights)));

    // Try to send SHM cap via the limited handle (which lacks send_shm) → E_PERM
    const rc = syscall.ipc_send_cap(limited_handle, &.{ shm_h, shm_rights });
    t.expectEqual("§3.3.33", -2, rc);
    syscall.shutdown();
}
