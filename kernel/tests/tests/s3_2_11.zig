const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §3.2.11 — `futex_wait_val` with any non-8-byte-aligned address in the array returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Use a valid page address + 1 to get misaligned addr.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    const misaligned_addr = result.val2 + 1;
    // Call futex_wait_val with misaligned address in the addrs array.
    var addrs = [1]u64{misaligned_addr};
    var expected = [1]u64{0};
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(syscall.SyscallNum.futex_wait_val)),
          [a0] "{rdi}" (@intFromPtr(&addrs)),
          [a1] "{rsi}" (@intFromPtr(&expected)),
          [a2] "{rdx}" (@as(u64, 1)),
          [a3] "{r10}" (@as(u64, 0)),
        : .{ .rcx = true, .r11 = true, .memory = true }
    );
    t.expectEqual("§3.2.11", E_INVAL, ret);
    syscall.shutdown();
}
