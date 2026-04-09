const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.16.2 — `send` with invalid target handle returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    const ret = syscall.ipc_send(9999, &.{0x42});
    t.expectEqual("§4.16.2", E_BADHANDLE, ret);
    syscall.shutdown();
}
