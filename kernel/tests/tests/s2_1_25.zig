const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.25 — `dead_process` entry has the same `field0` encoding as `process` (crash_reason + restart_count).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits())));

    // Wait for child to die.
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
    // Check field0 encoding: crash_reason(bits 0-4) = normal_exit(12), restart_count(bits 16-31) = 0.
    const crash_reason = view[slot].processCrashReason();
    const restart_count = view[slot].processRestartCount();
    if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS and crash_reason == .normal_exit and restart_count == 0) {
        t.pass("§2.1.25");
    } else {
        t.fail("§2.1.25");
    }
    syscall.shutdown();
}
