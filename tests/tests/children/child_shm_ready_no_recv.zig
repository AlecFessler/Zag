const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

/// Child for §2.11.32: maps a SHM provided by the parent via cap transfer,
/// sets buf[0] = 1 to signal "alive and ready (but not recv'ing)", then
/// blocks on a futex at buf[1] forever. It never calls ipc_recv, so any
/// callers using ipc_call to this process pile up in the wait queue until
/// the parent revokes the child handle.
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

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @intCast(vm.val), 0) != 0) return;

    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);
    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1, .release);
    _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1);

    // Park forever.
    while (true) {
        _ = syscall.futex_wait(@as(*u64, @ptrCast(@volatileCast(&buf[1]))), 0, MAX_TIMEOUT);
    }
}
