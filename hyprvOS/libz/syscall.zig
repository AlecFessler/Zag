//! Cross-arch syscall wrappers for hyprvOS.
//!
//! Supports both x86_64 (`syscall` instruction, SysV AMD64 register layout)
//! and aarch64 (`svc #0`, x8=syscall number, x0..x4=args, x0=ret, x1=ret2).
//! The AArch64 ABI matches `kernel/arch/aarch64/exceptions.zig` which writes
//! the primary return in x0 and the secondary return (e.g. `mem_reserve`'s
//! allocated VA) in x1.

const builtin = @import("builtin");

pub const PAGE4K: u64 = 4096;

pub const SyscallResult2 = struct {
    val: i64,
    val2: u64,
};

// Error codes
pub const E_OK: i64 = 0;
pub const E_INVAL: i64 = -1;
pub const E_PERM: i64 = -2;
pub const E_BADHANDLE: i64 = -3;
pub const E_NOMEM: i64 = -4;
pub const E_MAXCAP: i64 = -5;
pub const E_BADADDR: i64 = -7;
pub const E_TIMEOUT: i64 = -8;
pub const E_AGAIN: i64 = -9;
pub const E_NOENT: i64 = -10;
pub const E_BUSY: i64 = -11;
pub const E_NODEV: i64 = -13;

// Syscall numbers — must match kernel/arch/syscall.zig SyscallNum enum exactly
pub const SyscallNum = enum(u64) {
    write, // 0
    mem_reserve, // 1
    mem_perms, // 2
    mem_shm_create, // 3
    mem_shm_map, // 4
    mem_shm_unmap, // 5
    mem_mmio_map, // 6
    mem_mmio_unmap, // 7
    proc_create, // 8
    thread_create, // 9
    thread_exit, // 10
    thread_yield, // 11
    set_affinity, // 12
    revoke_perm, // 13
    disable_restart, // 14
    futex_wait, // 15
    futex_wake, // 16
    clock_gettime, // 17
    ioport_read, // 18
    ioport_write, // 19
    mem_dma_map, // 20
    mem_dma_unmap, // 21
    pin_exclusive, // 22
    ipc_send, // 23
    ipc_call, // 24
    ipc_recv, // 25
    ipc_reply, // 26
    shutdown, // 27
    thread_self, // 28
    thread_suspend, // 29
    thread_resume, // 30
    thread_kill, // 31
    fault_recv, // 32
    fault_reply, // 33
    fault_read_mem, // 34
    fault_write_mem, // 35
    fault_set_thread_mode, // 36
    vm_create, // 37
    vm_destroy, // 38
    vm_guest_map, // 39
    vm_recv, // 40
    vm_reply, // 41
    vm_vcpu_set_state, // 42
    vm_vcpu_get_state, // 43
    vm_vcpu_run, // 44
    vm_vcpu_interrupt, // 45
    vm_sysreg_passthrough, // 46
    vm_intc_assert_irq, // 47
    vm_intc_deassert_irq, // 48
};

// Raw syscall wrappers
fn syscall0(num: SyscallNum) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@intFromEnum(num)),
            : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@intFromEnum(num)),
            : .{ .memory = true }),
        else => unreachable,
    };
}

fn syscall1(num: SyscallNum, a0: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@intFromEnum(num)),
              [a0] "{rdi}" (a0),
            : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@intFromEnum(num)),
              [a0] "{x0}" (a0),
            : .{ .memory = true }),
        else => unreachable,
    };
}

fn syscall2(num: SyscallNum, a0: u64, a1: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@intFromEnum(num)),
              [a0] "{rdi}" (a0),
              [a1] "{rsi}" (a1),
            : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@intFromEnum(num)),
              [a0] "{x0}" (a0),
              [a1] "{x1}" (a1),
            : .{ .memory = true }),
        else => unreachable,
    };
}

fn syscall3(num: SyscallNum, a0: u64, a1: u64, a2: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\syscall
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@intFromEnum(num)),
              [a0] "{rdi}" (a0),
              [a1] "{rsi}" (a1),
              [a2] "{rdx}" (a2),
            : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@intFromEnum(num)),
              [a0] "{x0}" (a0),
              [a1] "{x1}" (a1),
              [a2] "{x2}" (a2),
            : .{ .memory = true }),
        else => unreachable,
    };
}

fn syscall4(num: SyscallNum, a0: u64, a1: u64, a2: u64, a3: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\syscall
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@intFromEnum(num)),
              [a0] "{rdi}" (a0),
              [a1] "{rsi}" (a1),
              [a2] "{rdx}" (a2),
              [a3] "{r10}" (a3),
            : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@intFromEnum(num)),
              [a0] "{x0}" (a0),
              [a1] "{x1}" (a1),
              [a2] "{x2}" (a2),
              [a3] "{x3}" (a3),
            : .{ .memory = true }),
        else => unreachable,
    };
}

fn syscall5(num: SyscallNum, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\syscall
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@intFromEnum(num)),
              [a0] "{rdi}" (a0),
              [a1] "{rsi}" (a1),
              [a2] "{rdx}" (a2),
              [a3] "{r10}" (a3),
              [a4] "{r8}" (a4),
            : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@intFromEnum(num)),
              [a0] "{x0}" (a0),
              [a1] "{x1}" (a1),
              [a2] "{x2}" (a2),
              [a3] "{x3}" (a3),
              [a4] "{x4}" (a4),
            : .{ .memory = true }),
        else => unreachable,
    };
}

fn syscall3_2(num: SyscallNum, a0: u64, a1: u64, a2: u64) SyscallResult2 {
    var val2: u64 = undefined;
    const val = switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
              [out2] "={rdx}" (val2),
            : [num] "{rax}" (@intFromEnum(num)),
              [a0] "{rdi}" (a0),
              [a1] "{rsi}" (a1),
              [a2] "{rdx}" (a2),
            : .{ .rcx = true, .r11 = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
              [out2] "={x1}" (val2),
            : [num] "{x8}" (@intFromEnum(num)),
              [a0] "{x0}" (a0),
              [a1] "{x1}" (a1),
              [a2] "{x2}" (a2),
            : .{ .memory = true }),
        else => unreachable,
    };
    return .{ .val = val, .val2 = val2 };
}

// Public API

pub fn write(msg: []const u8) void {
    _ = syscall2(.write, @intFromPtr(msg.ptr), msg.len);
}

pub fn shutdown() noreturn {
    _ = syscall0(.shutdown);
    unreachable;
}

pub fn thread_exit() noreturn {
    _ = syscall0(.thread_exit);
    unreachable;
}

pub fn thread_yield() void {
    _ = syscall0(.thread_yield);
}

pub fn thread_self() i64 {
    return syscall0(.thread_self);
}

pub fn clock_gettime() u64 {
    return @bitCast(syscall0(.clock_gettime));
}

pub fn mem_reserve(hint: u64, size: u64, rights_bits: u64) SyscallResult2 {
    return syscall3_2(.mem_reserve, hint, size, rights_bits);
}

pub fn mem_mmio_map(device_handle: u64, vm_handle: u64, offset: u64) i64 {
    return syscall3(.mem_mmio_map, device_handle, vm_handle, offset);
}

pub fn shm_create_with_rights(size: u64, rights: u64) i64 {
    return syscall2(.mem_shm_create, size, rights);
}

pub fn mem_shm_map(shm_handle: u64, vm_handle: u64, offset: u64) i64 {
    return syscall3(.mem_shm_map, shm_handle, vm_handle, offset);
}

pub fn mem_dma_map(device_handle: u64, shm_handle: u64) i64 {
    return syscall2(.mem_dma_map, device_handle, shm_handle);
}

pub fn ioport_read(device_handle: u64, port_offset: u64, width: u64) i64 {
    return syscall3(.ioport_read, device_handle, port_offset, width);
}

pub fn ioport_write(device_handle: u64, port_offset: u64, width: u64, value: u64) i64 {
    return syscall4(.ioport_write, device_handle, port_offset, width, value);
}

pub fn vm_create(vcpu_count: u64, policy_ptr: u64) i64 {
    return syscall2(.vm_create, vcpu_count, policy_ptr);
}

pub fn vm_guest_map(vm_handle: u64, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    return syscall5(.vm_guest_map, vm_handle, host_vaddr, guest_addr, size, rights);
}

pub fn vm_recv(vm_handle: u64, buf_ptr: u64, blocking: u64) i64 {
    return syscall3(.vm_recv, vm_handle, buf_ptr, blocking);
}

pub fn vm_reply_action(vm_handle: u64, exit_token: u64, action_ptr: u64) i64 {
    return syscall3(.vm_reply, vm_handle, exit_token, action_ptr);
}

pub fn revoke_perm(handle: u64) i64 {
    return syscall1(.revoke_perm, handle);
}

pub fn vm_vcpu_set_state(thread_handle: u64, guest_state_ptr: u64) i64 {
    return syscall2(.vm_vcpu_set_state, thread_handle, guest_state_ptr);
}

pub fn vm_vcpu_get_state(thread_handle: u64, guest_state_ptr: u64) i64 {
    return syscall2(.vm_vcpu_get_state, thread_handle, guest_state_ptr);
}

pub fn vm_vcpu_run(thread_handle: u64) i64 {
    return syscall1(.vm_vcpu_run, thread_handle);
}

pub fn vm_vcpu_interrupt(thread_handle: u64, interrupt_ptr: u64) i64 {
    return syscall2(.vm_vcpu_interrupt, thread_handle, interrupt_ptr);
}

pub fn vm_intc_assert_irq(vm_handle: u64, irq_num: u64) i64 {
    return syscall2(.vm_intc_assert_irq, vm_handle, irq_num);
}

pub fn vm_intc_deassert_irq(vm_handle: u64, irq_num: u64) i64 {
    return syscall2(.vm_intc_deassert_irq, vm_handle, irq_num);
}
