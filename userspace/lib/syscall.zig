pub const PAGE4K: u64 = 4096;

pub const SyscallResult2 = struct {
    val: i64,
    val2: u64,
};

pub const SyscallNum = enum(u64) {
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
};

fn syscall0(num: SyscallNum) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }
    );
}

fn syscall1(num: SyscallNum, a0: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }
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

fn syscall3(num: SyscallNum, a0: u64, a1: u64, a2: u64) i64 {
    return asm volatile (
        \\int $0x80
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
          [a2] "{rdx}" (a2),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }
    );
}

fn syscall4(num: SyscallNum, a0: u64, a1: u64, a2: u64, a3: u64) i64 {
    return asm volatile (
        \\int $0x80
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r10}" (a3),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }
    );
}

fn syscall3_2(num: SyscallNum, a0: u64, a1: u64, a2: u64) SyscallResult2 {
    var val2: u64 = undefined;
    const val = asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
          [out2] "={rdx}" (val2),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
          [a2] "{rdx}" (a2),
        : .{ .rcx = true, .r11 = true, .memory = true }
    );
    return .{ .val = val, .val2 = val2 };
}

pub fn write(msg: []const u8) void {
    _ = syscall2(.write, @intFromPtr(msg.ptr), msg.len);
}

pub fn vm_reserve(hint: u64, size: u64, rights_bits: u64) SyscallResult2 {
    return syscall3_2(.vm_reserve, hint, size, rights_bits);
}

pub fn vm_perms(vm_handle: u64, offset: u64, size: u64, rights_bits: u64) i64 {
    return syscall4(.vm_perms, vm_handle, offset, size, rights_bits);
}

pub fn shm_create(size: u64) i64 {
    return syscall1(.shm_create, size);
}

pub fn shm_map(shm_handle: u64, vm_handle: u64, offset: u64) i64 {
    return syscall3(.shm_map, shm_handle, vm_handle, offset);
}

pub fn shm_unmap(shm_handle: u64, vm_handle: u64) i64 {
    return syscall2(.shm_unmap, shm_handle, vm_handle);
}

pub fn mmio_map(device_handle: u64, vm_handle: u64, offset: u64) i64 {
    return syscall3(.mmio_map, device_handle, vm_handle, offset);
}

pub fn mmio_unmap(device_handle: u64, vm_handle: u64) i64 {
    return syscall2(.mmio_unmap, device_handle, vm_handle);
}

pub fn proc_create(elf_ptr: u64, elf_len: u64, rights_bits: u64) i64 {
    return syscall3(.proc_create, elf_ptr, elf_len, rights_bits);
}

pub fn thread_create(entry: *const fn () void, arg: u64, num_stack_pages: u64) i64 {
    return syscall3(.thread_create, @intFromPtr(entry), arg, num_stack_pages);
}

pub fn thread_exit() noreturn {
    _ = syscall0(.thread_exit);
    unreachable;
}

pub fn thread_yield() void {
    _ = syscall0(.thread_yield);
}

pub fn set_affinity(core_mask: u64) i64 {
    return syscall1(.set_affinity, core_mask);
}

pub fn grant_perm(src_handle: u64, target_proc_handle: u64, rights_bits: u64) i64 {
    return syscall3(.grant_perm, src_handle, target_proc_handle, rights_bits);
}

pub fn revoke_perm(handle: u64) i64 {
    return syscall1(.revoke_perm, handle);
}

pub fn disable_restart() i64 {
    return syscall0(.disable_restart);
}

pub fn futex_wait(addr: *const u64, expected: u64) i64 {
    return syscall2(.futex_wait, @intFromPtr(addr), expected);
}

pub fn futex_wake(addr: *const u64, count: u64) i64 {
    return syscall2(.futex_wake, @intFromPtr(addr), count);
}

pub fn clock_gettime() i64 {
    return syscall0(.clock_gettime);
}

