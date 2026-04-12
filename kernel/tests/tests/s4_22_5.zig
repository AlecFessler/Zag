const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.22.5 — `futex_wait` with invalid addr returns `E_BADADDR`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const E_BADADDR: i64 = -7;
    // Use an unmapped address (0xDEAD0000) which is 8-byte aligned but invalid.
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@as(u64, @intFromEnum(syscall.SyscallNum.futex_wait))),
          [a0] "{rdi}" (@as(u64, 0xDEAD0000)),
          [a1] "{rsi}" (@as(u64, 0)),
          [a2] "{rdx}" (@as(u64, 0)),
        : .{ .rcx = true, .r11 = true, .memory = true }
    );
    t.expectEqual("§4.22.5", E_BADADDR, ret);
    syscall.shutdown();
}
