const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives SHM via cap transfer, maps it, reads first u64, replies with value.
/// Used to verify cap transfer actually delivered the SHM to the receiver.
pub fn main(perm_view_addr: u64) void {
    // Receive IPC with cap transfer.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    // Find SHM handle in our perm view.
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }

    if (shm_handle == 0 or shm_size == 0) {
        // No SHM received — reply with sentinel.
        _ = syscall.ipc_reply(&.{0xDEAD});
        return;
    }

    // Map SHM and read first u64.
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) {
        _ = syscall.ipc_reply(&.{0xDEAD});
        return;
    }
    if (syscall.mem_shm_map(shm_handle, @bitCast(vm_result.val), 0) != 0) {
        _ = syscall.ipc_reply(&.{0xDEAD});
        return;
    }

    const ptr: *const volatile u64 = @ptrFromInt(vm_result.val2);
    const val = ptr.*;
    _ = syscall.ipc_reply(&.{val});
}
