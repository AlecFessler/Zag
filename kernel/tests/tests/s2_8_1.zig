const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.8.1 — Each user stack has a 1-page unmapped underflow guard below the usable region.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child_stack_overflow — it recurses until it hits the underflow guard page.
    // If the guard page exists, the child crashes with stack_overflow.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_stack_overflow.ptr), children.child_stack_overflow.len, child_rights.bits())));

    // Wait for child to die.
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

    // The child dying with stack_overflow proves the underflow guard exists.
    if (view[slot].processCrashReason() == .stack_overflow) {
        t.pass("§2.8.1");
    } else {
        t.fail("§2.8.1");
    }
    syscall.shutdown();
}
