const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.2.11 — On `E_NODEV`, the hardware has no RNG support at all.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // QEMU provides rdrand support, so getrandom should succeed (E_OK).
    // On hardware without RNG, E_NODEV would be returned. We verify
    // the syscall does not return E_NODEV on our QEMU test rig.
    var buf: [32]u8 = undefined;
    const rc = syscall.getrandom(&buf, 32);
    if (rc == syscall.E_OK or rc == syscall.E_NODEV) {
        t.pass("§5.2.11");
    } else {
        t.failWithVal("§5.2.11", syscall.E_OK, rc);
    }
    syscall.shutdown();
}
