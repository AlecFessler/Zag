const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Fills own perm table with vm_reserve calls, then blocks on recv.
/// Used to test E_MAXCAP when parent sends/calls with cap transfer.
pub fn main(_: u64) void {
    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        const r = syscall.vm_reserve(0, 4096, rw);
        if (r.val < 0) break;
    }
    // Block on recv — parent can now send/call with cap transfer
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});
    // Block forever
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
}
