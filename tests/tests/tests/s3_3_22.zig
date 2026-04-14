const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.3.22 — SHM capability transfer is non-exclusive (both sender and target retain handles).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Create SHM, write magic value.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, 4096, vm_rights);
    if (vm.val < 0) {
        t.fail("§3.3.22");
        syscall.shutdown();
    }
    _ = syscall.mem_shm_map(shm_handle, @bitCast(vm.val), 0);
    const ptr: *volatile u64 = @ptrFromInt(vm.val2);
    ptr.* = 0xBEEF_CAFE;

    // Send SHM to child via cap transfer.
    const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_verify_shm_transfer.ptr),
        children.child_verify_shm_transfer.len,
        child_rights,
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Verify child received the SHM (read back the magic value).
    const child_got_shm = reply.words[0] == 0xBEEF_CAFE;

    // Verify parent still has the SHM handle (non-exclusive).
    var still_has = false;
    for (0..128) |i| {
        if (view[i].handle == shm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            still_has = true;
            break;
        }
    }

    if (child_got_shm and still_has) {
        t.pass("§3.3.22");
    } else {
        t.fail("§3.3.22");
    }
    syscall.shutdown();
}
