const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.28 — Non-restartable dead process: parent's entry converts to `dead_process` with crash reason and restart count.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn a non-restartable child that exits immediately
    const child_rights = (perms.ProcessRights{}).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights)));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Wait for entry to become ENTRY_TYPE_DEAD_PROCESS
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    // Verify: entry type is dead_process, crash reason is normal_exit, restart count is 0
    const is_dead = view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS;
    const reason = view[slot].processCrashReason();
    const restart_count = view[slot].processRestartCount();
    if (is_dead and reason == .normal_exit and restart_count == 0) {
        t.pass("§2.6.28");
    } else {
        t.fail("§2.6.28");
    }
    syscall.shutdown();
}
