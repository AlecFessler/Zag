const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.2.17 — `futex_wait_change` with any non-8-byte-aligned address in the array returns `E_INVAL`.
pub fn main(_: u64) void {
    // Allocate a valid page and use a misaligned address within it.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    const misaligned_addr = result.val2 + 1;
    var addrs = [1]u64{misaligned_addr};
    const ret = syscall.futex_wait_change(@intFromPtr(&addrs), 1, 0);
    t.expectEqual("§3.2.17", syscall.E_INVAL, ret);
    syscall.shutdown();
}
