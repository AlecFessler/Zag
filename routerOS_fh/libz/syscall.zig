const lib = @import("lib");

pub const SysErr = error{
    InvalidArgument,
    PermissionDenied,
    BadCapability,
    OutOfMemory,
    MaxCapabilities,
    MaxThreads,
    BadAddress,
    Timeout,
    Again,
    NotFound,
    Busy,
    AlreadyExists,
};

fn err(code: i64) SysErr {
    return switch (code) {
        -1 => SysErr.InvalidArgument,
        -2 => SysErr.PermissionDenied,
        -3 => SysErr.BadCapability,
        -4 => SysErr.OutOfMemory,
        -5 => SysErr.MaxCapabilities,
        -6 => SysErr.MaxThreads,
        -7 => SysErr.BadAddress,
        -8 => SysErr.Timeout,
        -9 => SysErr.Again,
        -10 => SysErr.NotFound,
        -11 => SysErr.Busy,
        -12 => SysErr.AlreadyExists,
        else => @panic("Unknown syscall error code"),
    };
}

pub const Syscall = enum(u64) {
    write,
    vm_reserve,
    vm_perms,
    shm_create,
    shm_map,
    shm_unmap,
    mmio_map,
    mmio_unmap,
    proc_create,
    thread_create,
    thread_exit,
    thread_yield,
    set_affinity,
    grant_perm,
    revoke_perm,
    disable_restart,
    futex_wait,
    futex_wake,
    clock_gettime,
    shutdown,
    ioport_read,
    ioport_write,
    dma_map,
    dma_unmap,
    pin_exclusive,
    broadcast,
};

const TwoValRet = struct {
    ret0: i64,
    ret1: u64,
};

pub const VmReserveRet = struct {
    handle: i64,
    addr: u64,
};

fn syscall0(syscall: Syscall) i64 {
    return asm volatile (
        \\int $0x80
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(syscall)),
        : .{ .memory = true });
}

fn syscall1(syscall: Syscall, arg0: u64,) i64 {
    return asm volatile (
        \\int $0x80
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(syscall)),
          [arg0] "{rdi}" (arg0),
        : .{ .memory = true });
}

fn syscall2(syscall: Syscall, arg0: u64, arg1: u64,) i64 {
    return asm volatile (
        \\int $0x80
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(syscall)),
          [arg0] "{rdi}" (arg0),
          [arg1] "{rsi}" (arg1),
        : .{ .memory = true });
}

fn syscall3(syscall: Syscall, arg0: u64, arg1: u64, arg2: u64,) i64 {
    return asm volatile (
        \\int $0x80
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(syscall)),
          [arg0] "{rdi}" (arg0),
          [arg1] "{rsi}" (arg1),
          [arg2] "{rdx}" (arg2),
        : .{ .memory = true });
}

fn syscall4(syscall: Syscall, arg0: u64, arg1: u64, arg2: u64, arg3: u64,) i64 {
    return asm volatile (
        \\int $0x80
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(syscall)),
          [arg0] "{rdi}" (arg0),
          [arg1] "{rsi}" (arg1),
          [arg2] "{rdx}" (arg2),
          [arg3] "{r10}" (arg3),
        : .{ .memory = true });
}

fn syscall3_2(syscall: Syscall, arg0: u64, arg1: u64, arg2: u64,) TwoValRet {
    var ret0: i64 = 0;
    var ret1: u64 = 0;
    asm volatile (
        \\int $0x80
        : [ret0] "={rax}" (ret0),
          [ret1] "={rdx}" (ret1),
        : [num] "{rax}" (@intFromEnum(syscall)),
          [arg0] "{rdi}" (arg0),
          [arg1] "{rsi}" (arg1),
          [arg2] "{rdx}" (arg2),
        : .{ .memory = true });
    return TwoValRet{ .ret0 = ret0, .ret1 = ret1, };
}

pub fn write(msg: []const u8) SysErr!void {
    const ret = syscall2(.write, @intFromPtr(msg.ptr), msg.len);
    if (ret < 0) return err(ret);
}

pub fn thread_exit() noreturn {
    _ = syscall0(.thread_exit);
    unreachable;
}
