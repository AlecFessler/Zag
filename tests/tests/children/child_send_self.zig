const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

pub fn main(_: u64) void {
    // Wait for parent to call us.
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    // Reply with HANDLE_SELF via cap transfer — gives caller a second handle to us.
    const all_handle_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .send_process = true,
        .send_device = true,
        .kill = true,
        .grant = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, all_handle_rights });
}
