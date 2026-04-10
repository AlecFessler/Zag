const lib = @import("lib");

const syscall = lib.syscall;

/// Yields for many iterations before entering recv, guaranteeing that any
/// ipc_call issued by the parent immediately after spawn will be queued
/// in the target's FIFO wait queue before the server reaches recv.
/// Then receives one message and replies (increments word 0 by 1).
pub fn main(_: u64) void {
    // Yield a lot so that the parent's ipc_call has time to queue.
    var i: u32 = 0;
    while (i < 500) : (i += 1) {
        syscall.thread_yield();
    }
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    msg.words[0] += 1;
    _ = syscall.ipc_reply(msg.words[0..msg.word_count]);
}
