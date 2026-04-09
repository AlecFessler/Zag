const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.15.4 — `pin_exclusive` with multi-core affinity returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Explicitly set multi-core affinity (cores 0 and 1), then try pin_exclusive.
    _ = syscall.set_affinity(0b11);
    const ret = syscall.pin_exclusive();
    t.expectEqual("§4.15.4", -1, ret);
    syscall.shutdown();
}
