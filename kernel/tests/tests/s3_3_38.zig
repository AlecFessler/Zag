const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §3.3.38 — `send` cap transfer with fewer than 2 words returns `E_INVAL`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_sleep.ptr),
        children.child_sleep.len,
        child_rights.bits(),
    )));
    // Cap transfer requires at least 2 words (handle + rights); 1 word must return E_INVAL.
    const ret = syscall.ipc_send_cap(child_handle, &.{0x42});
    t.expectEqual("§3.3.38", E_INVAL, ret);
    syscall.shutdown();
}
