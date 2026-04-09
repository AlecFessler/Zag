const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.28.2 — `ioport_write` with invalid handle returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    const ret = syscall.ioport_write(0xFFFFFFFF, 0, 1, 0);
    t.expectEqual("§4.28.2", E_BADHANDLE, ret);
    syscall.shutdown();
}
