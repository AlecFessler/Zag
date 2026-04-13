const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.36 — Fault on the underflow guard (below stack) kills with fault reason `stack_overflow` (§6).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_stack_overflow.ptr), children.child_stack_overflow.len, child_rights.bits())));

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

    t.expectEqual("§2.2.36", @intFromEnum(perm_view.CrashReason.stack_overflow), @as(i64, @intFromEnum(view[slot].processCrashReason())));
    syscall.shutdown();
}
