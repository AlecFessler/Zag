const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.27.2 — `ioport_read` with invalid handle returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    const ret = syscall.ioport_read(0xFFFFFFFF, 0, 1);
    t.expectEqual("§4.27.2", E_BADHANDLE, ret);
    syscall.shutdown();
}
