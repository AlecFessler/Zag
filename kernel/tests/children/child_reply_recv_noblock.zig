const lib = @import("lib");

const syscall = lib.syscall;

/// Receives call, does reply+recv(non-blocking). The recv part should return E_AGAIN.
/// Then does a blocking recv for a second call. Reports the E_AGAIN result.
pub fn main(_: u64) void {
    // First: receive a call
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    // Reply and attempt atomic non-blocking recv
    var msg2: syscall.IpcMessage = .{};
    const rc = syscall.ipc_reply_recv(&.{}, false, &msg2);
    // rc should be E_AGAIN (-9) since no second message is pending
    // Now wait for a second call to report the result
    var msg3: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg3) != 0) return;
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
