const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Tries shm_create and reports result via IPC reply.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();
    const rc = syscall.shm_create_with_rights(4096, shm_rights);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
