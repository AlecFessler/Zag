const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.19.4 — `reply` with capability transfer flag transfers a capability to the caller.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn child_send_self which replies with HANDLE_SELF via cap transfer.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self.ptr), children.child_send_self.len, child_rights.bits())));

    // Call the child — it will reply with cap transfer of its HANDLE_SELF.
    var reply: syscall.IpcMessage = .{};
    const ret = syscall.ipc_call(child_handle, &.{}, &reply);

    if (ret != 0) {
        t.fail("§4.19.4");
        syscall.shutdown();
    }

    // Find the NEW process handle (not child_handle, not HANDLE_SELF).
    var new_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and view[i].handle != child_handle)
        {
            new_handle = view[i].handle;
            break;
        }
    }

    if (new_handle == 0) {
        t.fail("§4.19.4");
        syscall.shutdown();
    }

    // Verify the new handle actually refers to the same child by calling IPC on it.
    // child_send_self already exited after replying, so this should return E_BADHANDLE
    // on the new handle too (both handles point to the same dead process).
    // Wait for child to die first.
    var attempts: u32 = 0;
    while (attempts < 10000) : (attempts += 1) {
        var dead = false;
        for (0..128) |i| {
            if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
                dead = true;
                break;
            }
        }
        if (dead) break;
        syscall.thread_yield();
    }

    // Both handles should now see the child as dead.
    var orig_dead = false;
    var new_dead = false;
    for (0..128) |i| {
        if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) orig_dead = true;
        if (view[i].handle == new_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) new_dead = true;
    }

    // Also try IPC on the new handle to trigger lazy conversion.
    var msg: syscall.IpcMessage = .{};
    const ipc_ret = syscall.ipc_call(new_handle, &.{0}, &msg);

    if (orig_dead and (new_dead or ipc_ret == -3)) {
        t.pass("§4.19.4");
    } else {
        t.fail("§4.19.4");
    }
    syscall.shutdown();
}
