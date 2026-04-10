const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.15.3 — `pin_exclusive` without single-core affinity returns `E_INVAL`.
///
/// Distinct from §4.15.4 (multi-core mask): this test relies on the default
/// thread affinity (all cores, inherited at process start) — i.e. no explicit
/// `set_affinity` call has narrowed the mask to a single core.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.pin_exclusive();
    t.expectEqual("§4.15.3", E_INVAL, ret);
    syscall.shutdown();
}
