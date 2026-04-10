const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

/// Child for §2.11.21 (FIFO ordering).
///
/// Protocol:
///   1. Recv setup cap-transfer of SHM, reply empty.
///   2. Map SHM. Set buf[0] = 1 ("alive, waiting for go signal").
///   3. Block on futex at buf[1] until parent writes buf[1] != 0
///      (parent only does this after it has explicitly ordered both callers
///      into the wait queue).
///   4. Recv + reply twice with monotonic counter (1, 2) so the parent can
///      verify the FIFO dequeue order.
pub fn main(perm_view_addr: u64) void {
    var setup_msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &setup_msg) != 0) return;
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
    const vm = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm.val < 0) return;
    if (syscall.shm_map(shm_handle, @intCast(vm.val), 0) != 0) return;

    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1, .release);
    _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1);

    // Wait for parent's "go" signal at buf[1].
    while (@atomicLoad(u64, @as(*u64, @ptrCast(@volatileCast(&buf[1]))), .acquire) == 0) {
        _ = syscall.futex_wait(@as(*u64, @ptrCast(@volatileCast(&buf[1]))), 0, MAX_TIMEOUT);
    }

    var counter: u64 = 0;
    var iter: u32 = 0;
    while (iter < 2) : (iter += 1) {
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;
        counter += 1;
        if (syscall.ipc_reply(&.{counter}) != 0) return;
    }

    // Park.
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, MAX_TIMEOUT);
}
