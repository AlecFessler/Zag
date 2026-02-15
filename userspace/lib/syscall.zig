const lib = @import("lib.zig");

pub const PAGE4K: u64 = 4096;

pub const SyscallResult2 = struct {
    val: i64,
    val2: u64,
};

pub const SyscallNum = enum(u64) {
    write,
    mem_reserve,
    mem_perms,
    proc_create,
    thread_create,
    thread_exit,
    thread_yield,
    thread_set_affinity,
    grant_perm,
    revoke_perm,
    futex_wait,
    futex_wake,
    clock_gettime,
};

fn syscall0(num: SyscallNum) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
        : .{ .rcx = true, .r11 = true, .memory = true }
    );
}

fn syscall1(num: SyscallNum, a0: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
        : .{ .rcx = true, .r11 = true, .memory = true }
    );
}

fn syscall2(num: SyscallNum, a0: u64, a1: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }
    );
}

fn syscall4(num: SyscallNum, a0: u64, a1: u64, a2: u64, a3: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r10}" (a3),
        : .{ .rcx = true, .r11 = true, .memory = true }
    );
}

fn syscall4_2(num: SyscallNum, a0: u64, a1: u64, a2: u64, a3: u64) SyscallResult2 {
    var val2: u64 = undefined;
    const val = asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
          [out2] "={rdx}" (val2),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r10}" (a3),
        : .{ .rcx = true, .r11 = true, .memory = true }
    );
    return .{ .val = val, .val2 = val2 };
}

pub fn write(msg: []const u8) void {
    _ = syscall2(.write, @intFromPtr(msg.ptr), msg.len);
}

pub fn mem_reserve(size: u64, rights: lib.perms.VmReservationRights) SyscallResult2 {
    return syscall4_2(.mem_reserve, 0, size, rights.bits(), 0);
}

pub fn thread_exit() noreturn {
    _ = syscall0(.thread_exit);
    unreachable;
}
