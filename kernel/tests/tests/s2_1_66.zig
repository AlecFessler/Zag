const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.66 — Parent's `process` entry is converted to `dead_process` when the child dies without restarting.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn non-restartable child.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits())));

    // Verify it starts as process type.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    const started_as_process = view[slot].entry_type == perm_view.ENTRY_TYPE_PROCESS;

    // Wait for conversion to dead_process.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    if (started_as_process and view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
        t.pass("§2.1.66");
    } else {
        t.fail("§2.1.66");
    }
    syscall.shutdown();
}
