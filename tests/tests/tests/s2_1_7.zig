const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.7 — If multiple processes hold handles to a dead process, revoking one does not invalidate the others.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child_send_self — it replies with HANDLE_SELF via cap transfer, giving us h2.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const h1: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self.ptr), children.child_send_self.len, child_rights.bits())));

    // Call child — child replies with HANDLE_SELF cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(h1, &.{}, &reply);

    // Find the second handle (process entry that isn't h1 and isn't our HANDLE_SELF).
    var h2: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and view[i].handle != h1 and view[i].handle != 0) {
            h2 = view[i].handle;
            break;
        }
    }
    if (h2 == 0) {
        t.fail("§2.1.7");
        syscall.shutdown();
    }

    // Wait for child to die.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        var found_dead = false;
        for (0..128) |i| {
            if (view[i].handle == h1 and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
                found_dead = true;
                break;
            }
        }
        if (found_dead) break;
        syscall.thread_yield();
    }

    // Now we hold two handles to the same dead process: h1 and h2.
    // Both should be dead_process.
    var h1_dead = false;
    var h2_dead = false;
    for (0..128) |i| {
        if (view[i].handle == h1 and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) h1_dead = true;
        if (view[i].handle == h2 and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) h2_dead = true;
    }
    if (!h1_dead or !h2_dead) {
        t.fail("§2.1.7");
        syscall.shutdown();
    }

    // Revoke h1.
    _ = syscall.revoke_perm(h1);

    // h2 should still be valid (dead_process).
    var h2_still_valid = false;
    for (0..128) |i| {
        if (view[i].handle == h2 and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
            h2_still_valid = true;
            break;
        }
    }

    if (h2_still_valid) {
        t.pass("§2.1.7");
    } else {
        t.fail("§2.1.7");
    }
    syscall.shutdown();
}
