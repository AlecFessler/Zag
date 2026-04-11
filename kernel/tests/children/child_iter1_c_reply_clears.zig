const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

/// Child for §2.11.17 (reply-to-send clears pending state).
///
/// Protocol:
///   1. Recv setup cap-transfer of SHM, reply empty.
///   2. Map SHM.
///   3. Recv the parent's send; reply empty (this is the reply-to-send
///      that must clear pending).
///   4. Set buf[0] = 1 ("first reply done — about to enter second recv").
///   5. Enter second recv. If it returns E_BUSY, write buf[1] = rc as the
///      failure signal. Otherwise reply with words[0] + 1 so the parent's
///      follow-up ipc_call observes a real reply.
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
    const vm = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @intCast(vm.val), 0) != 0) return;

    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    // Signal ready so parent knows it can issue the ipc_send.
    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1, .release);
    _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1);

    // Receive the send and reply (clears pending per §2.11.17).
    var msg1: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg1) != 0) return;
    if (syscall.ipc_reply(&.{}) != 0) return;

    // Signal post-reply so the parent knows the reply-to-send completed.
    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[0]))), 2, .release);
    _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1);

    // Enter the second recv. If pending was NOT cleared, this returns
    // E_BUSY immediately.
    var msg2: syscall.IpcMessage = .{};
    const rc = syscall.ipc_recv(true, &msg2);
    if (rc != 0) {
        @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[1]))), @bitCast(rc), .release);
        _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[1]))), 1);
        return;
    }

    // Mark second recv success and reply so the parent's call completes.
    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[2]))), 1, .release);
    msg2.words[0] += 1;
    _ = syscall.ipc_reply(msg2.words[0..msg2.word_count]);

    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, MAX_TIMEOUT);
}
