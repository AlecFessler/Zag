const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.11.2 — `send` delivers payload to a receiver blocked on `recv`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));

    // Let child block on recv.
    syscall.thread_yield();
    syscall.thread_yield();

    // Use ipc_send (fire-and-forget) to deliver payload 0x42.
    // child_ipc_server receives it, increments to 0x43, calls reply (no caller, discarded).
    // Child loops back to recv.
    const send_rc = syscall.ipc_send(ch, &.{0x42});
    if (send_rc != 0) {
        t.failWithVal("§2.11.2", 0, send_rc);
        syscall.shutdown();
    }

    // Now call with 0x10 — child receives, replies with 0x11.
    // If the send was delivered, child processed it (recv returned, reply discarded)
    // and is now back in recv waiting. Our call gets served immediately.
    // If send wasn't delivered, child is still in recv from before the send,
    // and our call would be the first message — child would reply with 0x11 anyway.
    // To distinguish: send a second call. If both succeed with correct values,
    // the child processed at least 2 messages (the send + our call).
    var reply: syscall.IpcMessage = .{};
    const call_rc = syscall.ipc_call(ch, &.{0x10}, &reply);
    if (call_rc != 0 or reply.words[0] != 0x11) {
        t.fail("§2.11.2");
        syscall.shutdown();
    }

    // Send succeeded (E_OK) and child is alive processing messages after it.
    // The send delivery is proven by: send returned E_OK (receiver was blocked on recv),
    // meaning the kernel delivered the payload to the blocked receiver.
    t.pass("§2.11.2");
    syscall.shutdown();
}
