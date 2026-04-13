// Child for 4194d05 PoC. Recv one msg, reply with HANDLE_SELF + fault_handler
// cap transfer. This is the attacker: sender of a fault_handler grant without
// actually holding ProcessRights.fault_handler.
const lib = @import("lib");
const perms = lib.perms;
const syscall = lib.syscall;

pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });
    syscall.thread_exit();
}
