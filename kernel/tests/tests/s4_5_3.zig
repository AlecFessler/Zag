const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.5.3 — `mem_shm_create` with zero size returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.shm_create_with_rights(0, 0x03);
    t.expectEqual("§4.5.3", E_INVAL, ret);
    syscall.shutdown();
}
