const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.17.2 — `call` with invalid target handle returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(0xDEAD, &.{}, &reply);
    t.expectEqual("§4.17.2", E_BADHANDLE, rc);
    syscall.shutdown();
}
