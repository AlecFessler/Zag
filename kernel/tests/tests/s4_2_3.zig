const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.2.3 — `write` with `len > 4096` returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.write_raw(0x1000, 4097);
    t.expectEqual("§4.2.3", E_INVAL, ret);
    syscall.shutdown();
}
