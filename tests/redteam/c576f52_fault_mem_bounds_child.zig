// Child for c576f52 PoC. Mirrors child_fault_after_transfer:
// receives one IPC, replies with HANDLE_SELF + fault_handler cap transfer
// (so the parent ends up holding fault_handler on this child), then null
// derefs to fault into the parent's fault box.
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
    lib.fault.nullDeref();
}
