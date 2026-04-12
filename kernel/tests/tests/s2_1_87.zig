const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.87 — `proc_create` with child perms exceeding parent's own process rights returns `E_PERM`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Spawn a child with spawn_process + spawn_thread but NOT device_own.
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .spawn_process = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_escalate.ptr),
        children.child_try_escalate.len,
        child_rights,
    )));

    // Tell the child to try proc_create with device_own — an escalated right it doesn't have.
    const escalated = (perms.ProcessRights{ .spawn_thread = true, .device_own = true }).bits();
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(ch, &.{escalated}, &reply);
    if (rc != 0) {
        t.failWithVal("§2.1.87", 0, rc);
        syscall.shutdown();
    }

    const child_ret: i64 = @bitCast(reply.words[0]);
    if (child_ret == -2) {
        t.pass("§2.1.87");
    } else {
        t.failWithVal("§2.1.87", -2, child_ret);
    }
    syscall.shutdown();
}
