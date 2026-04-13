const lib = @import("lib");

const syscall = lib.syscall;

/// IPC echo server for cross-process IPC benchmarking.
/// Pins to core 1 for stable cross-core measurements, then enters
/// a blocking recv loop and replies with the same words until killed.
pub fn main(_: u64) void {
    _ = syscall.set_affinity(2); // core 1
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    while (true) {
        var msg: syscall.IpcMessage = .{};
        const rc = syscall.ipc_recv(true, &msg);
        if (rc != 0) return;

        if (!msg.from_call) continue;

        _ = syscall.ipc_reply(msg.words[0..msg.word_count]);
    }
}
