const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.11.1 — `send` is non-blocking: the sender continues running after delivery.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));
    // Let child start and block on recv
    syscall.thread_yield();
    syscall.thread_yield();
    // Send is non-blocking — we continue immediately after.
    // Reaching the code after ipc_send proves non-blocking: if send blocked
    // indefinitely (like call does), we would never execute past it and the
    // test would time out rather than pass.
    const rc = syscall.ipc_send(ch, &.{0x42});
    if (rc == 0) {
        t.pass("§2.11.1");
    } else {
        t.fail("§2.11.1");
    }
    syscall.shutdown();
}
