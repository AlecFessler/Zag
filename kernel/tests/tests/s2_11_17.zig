const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.11.17 — `reply` to a `send` clears the pending state.
pub fn main(_: u64) void {
    // child_ipc_server: recv -> reply -> recv (loop).
    // Send (not call) first: child receives, replies (clears pending), loops to recv.
    // If reply didn't clear pending, the next recv would fail.
    // Then call: if pending was properly cleared, child can recv and reply normally.
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));

    // Let child block on recv
    syscall.thread_yield();
    syscall.thread_yield();

    // Send (fire-and-forget) — child receives, replies (clears pending), loops to recv
    const send_rc = syscall.ipc_send(ch, &.{0x42});
    if (send_rc != 0) {
        t.failWithVal("§2.11.17 [send failed]", 0, send_rc);
        syscall.shutdown();
    }

    // Call — if pending was cleared, child can recv again and reply
    var reply: syscall.IpcMessage = .{};
    const call_rc = syscall.ipc_call(ch, &.{0x10}, &reply);
    if (call_rc == 0 and reply.words[0] == 0x11) {
        t.pass("§2.11.17");
    } else {
        t.fail("§2.11.17");
    }
    syscall.shutdown();
}
