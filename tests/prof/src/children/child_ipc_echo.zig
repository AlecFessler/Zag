const lib = @import("lib");

const syscall = lib.syscall;

/// IPC ping-pong peer. Blocks on ipc_recv; echoes the message back with
/// word[0] incremented. Runs forever — the parent ping-pong loop is what
/// drives kprof; this child just keeps the other side of the pipe alive.
pub fn main(_: u64) void {
    while (true) {
        var msg: syscall.IpcMessage = .{};
        const recv_rc = syscall.ipc_recv(true, &msg);
        if (recv_rc != 0) break;
        if (msg.word_count == 0) {
            _ = syscall.ipc_reply(&.{0});
            continue;
        }
        msg.words[0] +%= 1;
        const reply_rc = syscall.ipc_reply(msg.words[0..msg.word_count]);
        if (reply_rc != 0) break;
    }
}
