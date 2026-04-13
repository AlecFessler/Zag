const lib = @import("lib");

const syscall = lib.syscall;

/// IPC echo server for cross-process IPC benchmarking.
/// Enters a blocking recv loop and replies with the same words
/// until the parent kills it.
pub fn main(_: u64) void {
    while (true) {
        var msg: syscall.IpcMessage = .{};
        const rc = syscall.ipc_recv(true, &msg);
        if (rc != 0) return;

        if (!msg.from_call) continue;

        _ = syscall.ipc_reply(msg.words[0..msg.word_count]);
    }
}
