const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.53 — Revoking a `dead_process` handle clears the slot.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits())));
    // Wait for child to become dead_process.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    // Revoke the dead_process handle.
    const revoke_ret = syscall.revoke_perm(child_handle);
    // Verify the slot is cleared.
    var still_found = false;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            still_found = true;
            break;
        }
    }
    if (revoke_ret == 0 and !still_found) {
        t.pass("§2.1.53");
    } else {
        t.fail("§2.1.53");
    }
    syscall.shutdown();
}
