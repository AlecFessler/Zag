const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Used for §2.11.11: verifies that blocking recv actually blocks until a
/// sender shows up. Parent supplies a SHM at setup; child maps it, records
/// clock_gettime into u64[0] *just before* recv, and into u64[1] *just after*
/// recv returns. If recv truly blocked, the gap between u64[0] (before the
/// parent's send) and u64[1] (after the send) will be observable.
///
/// Protocol:
///   1. Child recv (setup call): receive SHM via cap transfer, reply.
///   2. Child maps SHM, writes t0 (pre-recv timestamp) to buf[0], writes
///      sentinel 1 to buf[2] indicating we are about to block, then calls
///      blocking recv.
///   3. When parent sends, child's recv returns; child writes t1 to buf[1]
///      and sentinel 2 to buf[2], then replies.
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

    const t0: u64 = @bitCast(syscall.clock_gettime());
    buf[0] = t0;
    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[2]))), 1, .release); // about to block on recv
    _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[2]))), 1);

    var m: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &m) != 0) return;

    const t1: u64 = @bitCast(syscall.clock_gettime());
    buf[1] = t1;
    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[2]))), 2, .release);
    _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[2]))), 1);

    _ = syscall.ipc_reply(&.{});
}
