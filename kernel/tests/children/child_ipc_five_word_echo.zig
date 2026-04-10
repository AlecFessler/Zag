const lib = @import("lib");

const syscall = lib.syscall;

/// Receives a call with up to 5 words and replies with 5 words obtained by
/// adding 1, 2, 3, 4, 5 respectively. Used to verify all 5 reply payload
/// registers are populated on ipc_call (§2.11.8).
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const w0 = msg.words[0] + 1;
    const w1 = msg.words[1] + 2;
    const w2 = msg.words[2] + 3;
    const w3 = msg.words[3] + 4;
    const w4 = msg.words[4] + 5;
    _ = syscall.ipc_reply(&.{ w0, w1, w2, w3, w4 });
}
