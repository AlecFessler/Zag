const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.7.2 — `mem_shm_unmap` with invalid handle returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.mem_shm_unmap(99999, 99998);
    t.expectEqual("§4.7.2", E_BADHANDLE, ret);
    syscall.shutdown();
}
