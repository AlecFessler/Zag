const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.2.2 — `getrandom` is non-blocking.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Verify getrandom returns immediately (E_OK or E_AGAIN), never blocks.
    var buf: [32]u8 = undefined;
    const rc = syscall.getrandom(&buf, 32);
    // E_OK means success (non-blocking), E_AGAIN means RNG temporarily
    // unavailable (also non-blocking). Either confirms non-blocking behavior.
    if (rc == syscall.E_OK or rc == syscall.E_AGAIN) {
        t.pass("§5.2.2");
    } else {
        t.failWithVal("§5.2.2", 0, rc);
    }
    syscall.shutdown();
}
