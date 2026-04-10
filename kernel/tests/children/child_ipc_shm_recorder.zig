const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// IPC server that records received message words to SHM.
///
/// Protocol:
///   1. First IPC is a CALL with cap-transferred SHM. We map the SHM, reply,
///      then loop on recv.
///   2. On each subsequent ipc (send or call), we write into the SHM:
///        u64[0] = "received" sentinel (0xDEADBEEF)
///        u64[1] = msg.words[0]
///        u64[2] = msg.words[1]
///        u64[3] = msg.words[2]
///        u64[4] = msg.words[3]
///        u64[5] = msg.words[4]
///        u64[6] = msg.word_count
///      Then replies with words[0..word_count] where word_i = msg.words[i] + 1.
///   3. Before returning from recv on the NEXT message we pause on a futex
///      at u64[7] which the parent may use to hold the server mid-processing.
pub fn main(perm_view_addr: u64) void {
    // First IPC: parent cap-transfers SHM via ipc_call.
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
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;

    const buf: [*]volatile u64 = @ptrFromInt(vm_result.val2);

    while (true) {
        var m: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &m) != 0) return;

        buf[1] = m.words[0];
        buf[2] = m.words[1];
        buf[3] = m.words[2];
        buf[4] = m.words[3];
        buf[5] = m.words[4];
        buf[6] = @as(u64, m.word_count);
        @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[0]))), 0xDEADBEEF, .release);
        _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1);

        // Optionally hold mid-processing: spin while buf[7] == 1.
        while (@atomicLoad(u64, @as(*u64, @ptrCast(@volatileCast(&buf[7]))), .acquire) == 1) {
            syscall.thread_yield();
        }

        // Reply with all received words incremented by 1 so callers can
        // verify full 5-word round-trips (§2.11.8).
        var reply_words: [5]u64 = .{ 0, 0, 0, 0, 0 };
        const count = m.word_count;
        var k: u3 = 0;
        while (k < count) : (k += 1) {
            reply_words[k] = m.words[k] + 1;
        }
        _ = syscall.ipc_reply(reply_words[0..count]);
    }
}
