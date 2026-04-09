const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.8.3 — Each user stack has a 1-page unmapped overflow guard above the usable region.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // child_stack_underflow accesses the overflow guard page above the stack.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_stack_underflow.ptr), children.child_stack_underflow.len, child_rights.bits())));

    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }

    if (view[slot].processCrashReason() == .stack_underflow) {
        t.pass("§2.8.3");
    } else {
        t.fail("§2.8.3");
    }
    syscall.shutdown();
}
