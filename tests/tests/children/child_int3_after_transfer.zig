const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Receives IPC, replies with HANDLE_SELF via cap transfer with fault_handler
/// bit set, then executes int3 to trigger a #BP exception. Per §2.12.12 the
/// kernel should deliver a fault message with fault_reason = breakpoint (14)
/// rather than killing the process.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });
    lib.fault.breakpoint();
}
