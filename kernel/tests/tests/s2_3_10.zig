const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.3.10 — Transferred rights must be a subset of source rights.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Create SHM with read+write+grant (no execute).
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    // Spawn a child.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_shm_create = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self.ptr), children.child_send_self.len, child_rights.bits())));
    // Try to transfer with execute right (not in source) — should fail with E_PERM.
    // ipc_call_cap blocks until the child is ready to recv, so no yielding needed.
    const exceeding_rights: u64 = (perms.SharedMemoryRights{ .read = true, .write = true, .execute = true, .grant = true }).bits();
    var reply: syscall.IpcMessage = .{};
    const ret = syscall.ipc_call_cap(child_handle, &.{ shm_handle, exceeding_rights }, &reply);
    if (ret == E_PERM) {
        t.pass("§2.3.10");
    } else {
        t.failWithVal("§2.3.10", E_PERM, ret);
    }
    syscall.shutdown();
}
