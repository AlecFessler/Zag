const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.2.66 — `set_affinity` with invalid core IDs returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Bit 63 is far beyond any real core count.
    const ret = syscall.set_affinity(@as(u64, 1) << 63);
    t.expectEqual("§2.2.66", E_INVAL, ret);
    syscall.shutdown();
}
