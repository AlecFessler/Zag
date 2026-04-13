const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §3.2.23 — `futex_wake` with invalid addr returns `E_BADADDR`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const E_BADADDR: i64 = -7;
    // Use raw syscall with unmapped but 8-byte aligned address.
    const ret = switch (@import("builtin").cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@as(u64, @intFromEnum(syscall.SyscallNum.futex_wake))),
              [a0] "{rdi}" (@as(u64, 0xDEAD0000)),
              [a1] "{rsi}" (@as(u64, 1)),
            : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@as(u64, @intFromEnum(syscall.SyscallNum.futex_wake))),
              [a0] "{x0}" (@as(u64, 0xDEAD0000)),
              [a1] "{x1}" (@as(u64, 1)),
            : .{ .memory = true }),
        else => unreachable,
    };
    t.expectEqual("§3.2.23", E_BADADDR, ret);
    syscall.shutdown();
}
