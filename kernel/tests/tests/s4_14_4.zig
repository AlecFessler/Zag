const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.14.4 — `set_affinity` with invalid core IDs returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // QEMU has 4 cores (bits 0-3 valid). Bit 63 is an invalid core.
    const ret = syscall.set_affinity(1 << 63);
    t.expectEqual("§4.14.4", E_INVAL, ret);
    syscall.shutdown();
}
