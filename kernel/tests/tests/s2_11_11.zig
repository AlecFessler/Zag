const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.11.11 — `recv` with blocking flag blocks when the queue is empty.
pub fn main(_: u64) void {
    // child_ipc_server calls blocking recv. If no one sends, it blocks.
    // We call it — it receives (was blocked, now unblocked) and replies.
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));
    // Let child start and enter blocking recv
    syscall.thread_yield();
    syscall.thread_yield();
    // Now call — child was blocked on recv, wakes up and processes
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(ch, &.{0x42}, &reply);
    if (rc == 0) {
        t.pass("§2.11.11");
    } else {
        t.fail("§2.11.11");
    }
    syscall.shutdown();
}
