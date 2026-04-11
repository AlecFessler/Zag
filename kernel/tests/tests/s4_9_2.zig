const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.9.2 — `mem_mmio_unmap` with invalid handle returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    const ret = syscall.mem_mmio_unmap(0xFFFFFFFF, 0xFFFFFFFF);
    t.expectEqual("§4.9.2", E_BADHANDLE, ret);
    syscall.shutdown();
}
