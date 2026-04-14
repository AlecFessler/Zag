const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.1.88 — `proc_create` with `thread_rights` containing undefined bits returns `E_INVAL`.
pub fn main(_: u64) void {
    const child_proc_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true };
    // 0xFF has the upper 4 bits set, which are undefined/reserved in ThreadHandleRights.
    const ret = syscall.proc_create_with_thread_rights(
        @intFromPtr(children.child_exit.ptr),
        children.child_exit.len,
        child_proc_rights.bits(),
        0xFF,
    );
    t.expectEqual("§2.1.88", E_INVAL, ret);
    syscall.shutdown();
}
