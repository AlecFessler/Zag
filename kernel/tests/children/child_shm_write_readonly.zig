const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives a read-only SHM handle and writes to it, triggering invalid_write.
pub fn main(perm_view_addr: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

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
    if (shm_handle == 0 or shm_size == 0) return;

    // Map with read rights only (matching the SHM rights)
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;

    const map_rc = syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) return;

    // Write to read-only SHM — should trigger invalid_write
    const ptr: *volatile u8 = @ptrFromInt(vm_result.val2);
    ptr.* = 0;
}
