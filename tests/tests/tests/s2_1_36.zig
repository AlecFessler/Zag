const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.36 — When a fault kills a process, the fault reason is recorded.
/// Uses a *non-restartable* child so that the parent's entry actually
/// converts to `dead_process` (rather than restarting). The child stack-
/// overflows; the parent's slot must show ENTRY_TYPE_DEAD_PROCESS with
/// crash reason == stack_overflow.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_stack_overflow.ptr),
        children.child_stack_overflow.len,
        child_rights,
    )));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    // Wait for the child to become dead_process.
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }

    const is_dead = view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS;
    const reason = view[slot].processCrashReason();

    if (is_dead and reason == .stack_overflow) {
        t.pass("§2.1.36");
    } else {
        t.fail("§2.1.36");
    }
    syscall.shutdown();
}
