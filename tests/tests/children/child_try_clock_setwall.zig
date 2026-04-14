const lib = @import("lib");

const syscall = lib.syscall;

/// Child spawned without `set_time` right. Calls `clock_setwall`
/// and reports the return code to the parent via IPC.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const rc = syscall.clock_setwall(1_000_000_000);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
