const lib = @import("lib.zig");

pub const SyscallNum = enum(u64) {
    write = 0,
    mem_reserve = 1,
    mem_perms = 2,
    proc_create = 3,
    proc_destroy = 4,
    thread_create = 5,
    thread_exit = 6,
    thread_yield = 7,
    thread_set_affinity = 8,
    grant_perm = 9,
    revoke_perm = 10,
    futex_wait = 11,
    futex_wake = 12,
    clock_gettime = 13,
};

fn syscall0(num: SyscallNum) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn syscall1(num: SyscallNum, a0: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn syscall2(num: SyscallNum, a0: u64, a1: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn syscall4(num: SyscallNum, a0: u64, a1: u64, a2: u64, a3: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r10}" (a3),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

pub fn write(msg: []const u8) void {
    _ = syscall2(.write, @intFromPtr(msg.ptr), msg.len);
}
