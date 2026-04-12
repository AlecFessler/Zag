const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.17.1 — `getrandom` fills a userspace buffer with cryptographically random bytes sourced from the hardware RNG.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var buf: [64]u8 = .{0} ** 64;
    const rc = syscall.getrandom(&buf, 64);
    if (rc != 0) {
        t.failWithVal("§2.17.1", 0, rc);
        syscall.shutdown();
    }
    // Check that at least some bytes are non-zero (all-zero from a 64-byte
    // random fill is astronomically unlikely).
    var any_nonzero = false;
    for (buf) |b| {
        if (b != 0) {
            any_nonzero = true;
            break;
        }
    }
    if (any_nonzero) {
        t.pass("§2.17.1");
    } else {
        t.fail("§2.17.1");
    }
    syscall.shutdown();
}
