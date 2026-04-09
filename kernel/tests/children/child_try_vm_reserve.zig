const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Tries vm_reserve and reports result via IPC reply.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, 4096, rw);
    _ = syscall.ipc_reply(&.{@bitCast(result.val)});
}
