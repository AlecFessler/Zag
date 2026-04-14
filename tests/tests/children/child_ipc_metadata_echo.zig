const lib = @import("lib");

const syscall = lib.syscall;

/// IPC server that replies with the r14 metadata it received:
/// word[0] = word_count, word[1] = from_call (1 or 0).
/// Used to verify recv returns proper r14 metadata to the receiver.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    const recv_rc = syscall.ipc_recv(true, &msg);
    if (recv_rc != 0) return;

    const wc: u64 = msg.word_count;
    const fc: u64 = if (msg.from_call) 1 else 0;
    _ = syscall.ipc_reply(&.{ wc, fc });
}
