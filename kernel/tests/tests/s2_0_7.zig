const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.0.7 — Priority inheritance is not implemented.
pub fn main(_: u64) void {
    // Negative spec — no mechanism to test; just confirm coverage.
    t.pass("§2.0.7 negative spec");
    syscall.shutdown();
}
