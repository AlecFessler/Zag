const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.5.4 — `shm_create` with zero rights returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.shm_create_with_rights(4096, 0);
    t.expectEqual("§4.5.4", E_INVAL, ret);
    syscall.shutdown();
}
