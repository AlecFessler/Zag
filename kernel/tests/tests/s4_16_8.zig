const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.16.8 — `send` cap transfer: source lacks `grant` on transferred handle returns `E_PERM`.
pub fn main(_: u64) void {
    // Create SHM with read+write but NO grant.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));

    // Spawn child_ipc_server.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));

    // Sync: do a round-trip call to ensure child is in recv loop.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{0}, &reply);

    // Child loops back to recv. Yield to let it enter recv.
    for (0..10) |_| syscall.thread_yield();
    // Send SHM without grant → E_PERM.
    const rc = syscall.ipc_send_cap(ch, &.{ shm_handle, shm_rights.bits() });
    t.expectEqual("§4.16.8", E_PERM, rc);
    syscall.shutdown();
}
