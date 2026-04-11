const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

pub fn main(perm_view_addr: u64) void {
    // Receive SHM handle via IPC from parent (cap transfer inserts it into our perm table)
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    // Find SHM handle in perm view (already inserted by kernel cap transfer)
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
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

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;

    const map_rc = syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) return;

    const ptr: *u64 = @ptrFromInt(vm_result.val2);
    ptr.* = ptr.* + 1;
    _ = syscall.futex_wake(@ptrFromInt(vm_result.val2), 1);
}
