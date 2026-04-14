const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Receives IPC, replies with HANDLE_SELF via cap transfer with fault_handler bit set,
/// then triggers a null pointer dereference to fault.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });
    // Null dereference — triggers a fault routed to the parent (our fault handler).
    lib.fault.nullDeref();
}
