const lib = @import("lib");

const syscall = lib.syscall;

/// IPC echo server. First recv gets affinity + mode. Then enters
/// the echo loop using the requested mode (recv+reply or reply_recv).
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const affinity = msg.words[0];
    const use_reply_recv = msg.words[1];
    _ = syscall.set_affinity(affinity);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);
    _ = syscall.ipc_reply(&.{});

    if (use_reply_recv != 0) {
        // First recv to get into the loop
        if (syscall.ipc_recv(true, &msg) != 0) return;

        // Atomic reply+recv loop
        while (true) {
            const rc = syscall.ipc_reply_recv(
                msg.words[0..msg.word_count],
                true,
                &msg,
            );
            if (rc != 0) return;
        }
    } else {
        // Separate recv + reply loop
        while (true) {
            if (syscall.ipc_recv(true, &msg) != 0) return;
            if (!msg.from_call) continue;
            _ = syscall.ipc_reply(msg.words[0..msg.word_count]);
        }
    }
}
