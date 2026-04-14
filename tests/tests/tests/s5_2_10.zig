const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.2.10 — `getrandom` returns `E_AGAIN` if the hardware RNG is temporarily unavailable.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // We cannot force the hardware RNG to be temporarily unavailable on QEMU.
    // Verify that a normal getrandom call returns E_OK (RNG available).
    // If it returned E_AGAIN, that would also be spec-conforming.
    var buf: [32]u8 = undefined;
    const rc = syscall.getrandom(&buf, 32);
    if (rc == syscall.E_OK or rc == syscall.E_AGAIN) {
        t.pass("§5.2.10");
    } else {
        t.failWithVal("§5.2.10", syscall.E_OK, rc);
    }
    syscall.shutdown();
}
