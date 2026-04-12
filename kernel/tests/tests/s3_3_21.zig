const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §3.3.21 — SHM capability transfer requires the `grant` bit on the SHM handle.
pub fn main(_: u64) void {
    // Create SHM with read+write but NO grant.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));

    // Spawn child_ipc_server — it blocks on recv.
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));

    // Give child time to start and block on recv.
    syscall.thread_yield();
    syscall.thread_yield();

    // Try to send SHM via cap transfer — should fail because grant bit is missing.
    // Use ipc_send_cap (non-blocking) to avoid blocking if child isn't ready.
    const rc = syscall.ipc_send_cap(ch, &.{ shm_handle, shm_rights.bits() });
    t.expectEqual("§3.3.21", E_PERM, rc);
    syscall.shutdown();
}
