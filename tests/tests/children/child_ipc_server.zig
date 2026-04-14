const lib = @import("lib");

const syscall = lib.syscall;

/// Simple IPC echo server: receives a message, adds 1 to first word, replies.
/// Loops until killed.
pub fn main(_: u64) void {
    while (true) {
        var msg: syscall.IpcMessage = .{};
        const recv_rc = syscall.ipc_recv(true, &msg);
        if (recv_rc != 0) break;

        // Echo back with first word incremented
        msg.words[0] += 1;
        const reply_rc = syscall.ipc_reply(msg.words[0..msg.word_count]);
        if (reply_rc != 0) break;
    }
}
