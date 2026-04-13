const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.3.55 — `mem_unmap` with invalid vm_handle returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    const ret = syscall.mem_unmap(0xFFFFFFFF, 0, 4096);
    t.expectEqual("§2.3.55", E_BADHANDLE, ret);
    syscall.shutdown();
}
