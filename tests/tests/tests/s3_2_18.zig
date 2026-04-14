const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §3.2.18 — `futex_wait_change` with any invalid address in the array returns `E_BADADDR`.
pub fn main(_: u64) void {
    // Use an unmapped but 8-byte-aligned address.
    var addrs = [1]u64{0xDEAD0000};
    const ret = syscall.futex_wait_change(@intFromPtr(&addrs), 1, 0);
    t.expectEqual("§3.2.18", syscall.E_BADADDR, ret);
    syscall.shutdown();
}
