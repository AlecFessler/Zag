const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.12.18 — `fault_recv` returns `E_PERM` if the calling process holds neither its own `fault_handler` ProcessRights bit nor `fault_handler` on any process handle
/// fault_handler ProcessRights bit nor fault_handler on any process handle.
pub fn main(_: u64) void {
    // Spawn child_try_fault_recv WITHOUT fault_handler in ProcessRights.
    // The child will call fault_recv and report the result via IPC.
    const child_rights = perms.ProcessRights{};
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_fault_recv.ptr),
        children.child_try_fault_recv.len,
        child_rights.bits(),
    )));

    // Let child start and block on recv.
    syscall.thread_yield();
    syscall.thread_yield();

    // Send IPC to child to trigger its fault_recv attempt.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{0x1}, &reply);

    // Child replies with the fault_recv return code in words[0].
    const child_rc: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§2.12.18", E_PERM, child_rc);

    syscall.shutdown();
}
