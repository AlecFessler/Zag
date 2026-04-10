const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// `set_affinity` with empty mask returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.set_affinity(0);
    t.expectEqual("§4.14.3", E_INVAL, ret);
    syscall.shutdown();
}
