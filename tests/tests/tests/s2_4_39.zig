const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.4.39 — `mem_dma_unmap` with invalid handle returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    const ret = syscall.mem_dma_unmap(0xFFFFFFFF, 0xFFFFFFFF);
    t.expectEqual("§2.4.39", E_BADHANDLE, ret);
    syscall.shutdown();
}
