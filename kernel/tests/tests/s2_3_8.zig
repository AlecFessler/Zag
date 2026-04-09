const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.8 — Process handles are transferable if the `grant` bit is set.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // child_a blocks on recv (stays alive). child_b receives cap and checks perm_view.
    const child_a_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_a: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self.ptr),
        children.child_send_self.len,
        child_a_rights.bits(),
    )));

    const child_b: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_verify_proc_transfer.ptr),
        children.child_verify_proc_transfer.len,
        (perms.ProcessRights{ .spawn_thread = true }).bits(),
    )));

    // Transfer child_a's handle to child_b via cap transfer with grant bit.
    const handle_rights: u64 = (perms.ProcessHandleRights{ .send_words = true, .grant = true }).bits();
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call_cap(child_b, &.{ child_a, handle_rights }, &reply);
    if (rc != 0) {
        t.failWithVal("§2.3.8", 0, rc);
        syscall.shutdown();
    }
    // Child_b checks its perm_view for the received process handle and replies 1 if found.
    if (reply.words[0] == 1) {
        t.pass("§2.3.8");
    } else {
        t.fail("§2.3.8");
    }
    syscall.shutdown();
}
