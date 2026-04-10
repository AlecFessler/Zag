const lib = @import("lib");

const syscall = lib.syscall;

/// Replies with the runtime address of its own `main` symbol. Used to probe
/// the ASLR-randomized ELF load base per process.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const addr: u64 = @intFromPtr(&main);
    _ = syscall.ipc_reply(&.{addr});
}
