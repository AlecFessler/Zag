const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.15.3 — `pin_exclusive` without single-core affinity returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Explicitly set multi-core affinity (cores 0 and 1) so this doesn't
    // depend on the default affinity being all-cores.
    _ = syscall.set_affinity(0b11);
    const ret = syscall.pin_exclusive();
    t.expectEqual("§4.15.3", -1, ret);
    syscall.shutdown();
}
