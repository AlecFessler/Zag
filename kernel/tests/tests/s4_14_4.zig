const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;
const E_INVAL: i64 = -1;

/// Probe the system's core count by calling `set_affinity` with single-bit
/// masks. The kernel accepts bits `[0, num_cores)` and rejects the rest with
/// `E_INVAL` (§4.14.4). Returns the smallest bit index that is rejected —
/// equivalently the core count. The spec (§5) allows up to 64 cores, so this
/// loop is bounded.
fn probeCoreCount() u6 {
    var i: u6 = 0;
    while (i < 63) : (i += 1) {
        const mask: u64 = @as(u64, 1) << i;
        if (syscall.set_affinity(mask) != E_OK) return i;
    }
    // Bit 63 still accepted — all 64 cores are valid in this config.
    return 63;
}

/// §4.14.4 — `set_affinity` with invalid core IDs returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;

    const num_cores = probeCoreCount();
    // Restore affinity to a known-valid core so subsequent syscalls do not
    // inherit a stale invalid mask.
    _ = syscall.set_affinity(1);

    // First bit that the kernel must reject.
    if (num_cores >= 64) {
        // 64-core max config: every bit is valid; test cannot produce an
        // invalid single-bit mask. Use a mask with all bits set above the
        // highest valid core — none exist, so fall back to an out-of-range
        // composite mask via the upper nibble of a u128 cast isn't possible.
        // Instead, pass 0 (empty mask) — that path is §4.14.3 (E_INVAL too).
        // With 64 valid cores, there is no "invalid bit" mask, so skip the
        // strict check and assert the set_affinity contract directly via the
        // smallest composite that the kernel still must treat as invalid:
        // mask containing only an invalid bit is impossible — so the test
        // reduces to a no-op success.
        t.pass("§4.14.4 (64-core max config: no invalid bits to test)");
        syscall.shutdown();
    }
    const invalid_mask: u64 = @as(u64, 1) << @intCast(num_cores);
    const ret = syscall.set_affinity(invalid_mask);
    t.expectEqual("§4.14.4", E_INVAL, ret);
    syscall.shutdown();
}
