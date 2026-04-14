const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.1.5 — SHM transfer is non-exclusive (both sender and target retain handles).
/// handles). Parent creates an SHM, maps it, transfers it with cap transfer
/// to a child. Child maps the same SHM and writes a distinguishing magic.
/// Parent, through its retained mapping, reads the child's magic — proving
/// both sides share the backing and neither lost the handle.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));

    // Parent maps the SHM and zeros the cell it expects the child to write.
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, 4096, vm_rights);
    const vm_h: u64 = @bitCast(vm.val);
    if (syscall.mem_shm_map(shm_handle, vm_h, 0) != 0) {
        t.fail("§3.1.5");
        syscall.shutdown();
    }
    const cell: *volatile u64 = @ptrFromInt(vm.val2);
    cell.* = 0;

    // Spawn a child with enough rights to map the transferred SHM.
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
        .mem_shm_create = true,
    };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_shm_write_magic.ptr),
        children.child_shm_write_magic.len,
        child_rights.bits(),
    )));

    // Transfer the SHM via cap transfer. The child writes magic; reply
    // confirms completion.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Sender retains its SHM slot.
    var sender_still_has = false;
    for (0..128) |i| {
        if (view[i].handle == shm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            sender_still_has = true;
            break;
        }
    }

    // And the child's write is visible through the retained mapping.
    const observed = cell.*;
    const observed_expected = observed == 0xBEEF_F00D_CAFE_1234;

    if (sender_still_has and observed_expected) {
        t.pass("§3.1.5");
    } else {
        t.fail("§3.1.5");
    }
    syscall.shutdown();
}
