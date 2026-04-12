const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.1.90 — `proc_create` with an invalid `max_thread_priority` value returns `E_INVAL`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true };

    // Priority 7 is out of range (valid: 0-4).
    const r1 = syscall.proc_create_with_opts(
        @intFromPtr(children.child_exit.ptr),
        children.child_exit.len,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        7,
    );
    t.expectEqual("§2.1.90 priority=7", E_INVAL, r1);

    // Priority 0xFF is out of range.
    const r2 = syscall.proc_create_with_opts(
        @intFromPtr(children.child_exit.ptr),
        children.child_exit.len,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        0xFF,
    );
    t.expectEqual("§2.1.90 priority=0xFF", E_INVAL, r2);

    syscall.shutdown();
}
