const lib = @import("lib");

const syscall = lib.syscall;

/// IPC server that replies with a monotonic counter.
/// First caller served gets 1, second gets 2, etc.
var counter: u64 = 0;

pub fn main(_: u64) void {
    while (true) {
        var msg: syscall.IpcMessage = .{};
        const recv_rc = syscall.ipc_recv(true, &msg);
        if (recv_rc != 0) break;
        counter += 1;
        const reply_rc = syscall.ipc_reply(&.{counter});
        if (reply_rc != 0) break;
    }
}
