const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.7 — SHM transfer is non-exclusive (both sender and target retain handles).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    // Spawn child and transfer SHM.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .shm_create = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self.ptr), children.child_send_self.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);
    // After transfer, parent should still have the SHM handle.
    var still_has_shm = false;
    for (0..128) |i| {
        if (view[i].handle == shm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            still_has_shm = true;
            break;
        }
    }
    if (still_has_shm) {
        t.pass("§2.3.7");
    } else {
        t.fail("§2.3.7");
    }
    syscall.shutdown();
}
