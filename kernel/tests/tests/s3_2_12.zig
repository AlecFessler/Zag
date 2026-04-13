const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §3.2.12 — `futex_wait_val` with any invalid address in the array returns `E_BADADDR`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const E_BADADDR: i64 = -7;
    // Use an unmapped address (0xDEAD0000) which is 8-byte aligned but invalid.
    var addrs = [1]u64{0xDEAD0000};
    var expected = [1]u64{0};
    const ret = switch (@import("builtin").cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@as(u64, @intFromEnum(syscall.SyscallNum.futex_wait_val))),
              [a0] "{rdi}" (@intFromPtr(&addrs)),
              [a1] "{rsi}" (@intFromPtr(&expected)),
              [a2] "{rdx}" (@as(u64, 1)),
              [a3] "{r10}" (@as(u64, 0)),
            : .{ .rcx = true, .r11 = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@as(u64, @intFromEnum(syscall.SyscallNum.futex_wait_val))),
              [a0] "{x0}" (@intFromPtr(&addrs)),
              [a1] "{x1}" (@intFromPtr(&expected)),
              [a2] "{x2}" (@as(u64, 1)),
              [a3] "{x3}" (@as(u64, 0)),
            : .{ .memory = true }),
        else => unreachable,
    };
    t.expectEqual("§3.2.12", E_BADADDR, ret);
    syscall.shutdown();
}
