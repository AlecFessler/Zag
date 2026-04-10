const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Receives an SHM handle via IPC cap transfer, maps it, writes a known
/// magic to the first u64, and replies. Used by §2.3.7 to prove a SHM cap
/// transfer is non-exclusive — the sender retains its mapping and can read
/// back the receiver's write.
pub fn main(perm_view_addr: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

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
    if (shm_handle == 0 or shm_size == 0) {
        _ = syscall.ipc_reply(&.{0xDEAD});
        return;
    }

    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) {
        _ = syscall.ipc_reply(&.{0xDEAD});
        return;
    }
    if (syscall.shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) {
        _ = syscall.ipc_reply(&.{0xDEAD});
        return;
    }

    const ptr: *volatile u64 = @ptrFromInt(vm_result.val2);
    ptr.* = 0xBEEF_F00D_CAFE_1234;
    _ = syscall.ipc_reply(&.{0});

    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
}
