const lib = @import("lib");

const perms_ = lib.perms;

pub const PAGE4K: u64 = 4096;

// ── Kernel error codes ──────────────────────────────────────────────
pub const SystemError = error{
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
    Unknown,
};

fn mapError(code: i64) SystemError {
    return switch (code) {
        -1 => error.InvalidArgument,
        -2 => error.PermissionDenied,
        -3 => error.BadCapability,
        -4 => error.OutOfMemory,
        -5 => error.MaxCapabilities,
        -6 => error.MaxThreads,
        -7 => error.BadAddress,
        -8 => error.Timeout,
        -9 => error.Again,
        -10 => error.NotFound,
        -11 => error.Busy,
        -12 => error.AlreadyExists,
        else => error.Unknown,
    };
}

// ── Result types ────────────────────────────────────────────────────
pub const Handle = u64;

pub const VmResult = struct {
    handle: Handle,
    addr: u64,
};

pub const SyscallResult2 = struct {
    val: i64,
    val2: u64,
};

// ── Syscall numbers ─────────────────────────────────────────────────
pub const SyscallNum = enum(u64) {
    write,
    mem_reserve,
    mem_perms,
    mem_shm_create,
    mem_shm_map,
    mem_shm_unmap,
    mem_mmio_map,
    mem_mmio_unmap,
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
    ioport_read,
    ioport_write,
    mem_dma_map,
    mem_dma_unmap,
    pin_exclusive,
    broadcast,
};

// ── Raw syscall wrappers ────────────────────────────────────────────
fn syscall0(num: SyscallNum) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
}

fn syscall1(num: SyscallNum, a0: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
}

fn syscall2(num: SyscallNum, a0: u64, a1: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
}

fn syscall3(num: SyscallNum, a0: u64, a1: u64, a2: u64) i64 {
    return asm volatile (
        \\int $0x80
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
          [a2] "{rdx}" (a2),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
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
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
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
        : .{ .rcx = true, .r11 = true, .memory = true });
    return .{ .val = val, .val2 = val2 };
}

// ── Public API ──────────────────────────────────────────────────────

pub fn write(msg: []const u8) void {
    _ = syscall2(.write, @intFromPtr(msg.ptr), msg.len);
}

pub fn mem_reserve(hint: u64, size: u64, rights_bits: u64) SystemError!VmResult {
    const result = syscall3_2(.mem_reserve, hint, size, rights_bits);
    if (result.val < 0) return mapError(result.val);
    return .{ .handle = @intCast(result.val), .addr = result.val2 };
}

pub fn mem_perms(vm_handle: Handle, offset: u64, size: u64, rights_bits: u64) SystemError!void {
    const rc = syscall4(.mem_perms, vm_handle, offset, size, rights_bits);
    if (rc < 0) return mapError(rc);
}

pub fn mem_shm_create(size: u64) SystemError!Handle {
    return shm_create_with_rights(size, (perms_.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits());
}

pub fn shm_create_with_rights(size: u64, rights: u64) SystemError!Handle {
    const rc = syscall2(.mem_shm_create, size, rights);
    if (rc < 0) return mapError(rc);
    return @intCast(rc);
}

pub fn mem_shm_map(shm_handle: Handle, vm_handle: Handle, offset: u64) SystemError!void {
    const rc = syscall3(.mem_shm_map, shm_handle, vm_handle, offset);
    if (rc < 0) return mapError(rc);
}

pub fn mem_shm_unmap(shm_handle: Handle, vm_handle: Handle) void {
    _ = syscall2(.mem_shm_unmap, shm_handle, vm_handle);
}

pub fn mem_mmio_map(device_handle: Handle, vm_handle: Handle, offset: u64) SystemError!void {
    const rc = syscall3(.mem_mmio_map, device_handle, vm_handle, offset);
    if (rc < 0) return mapError(rc);
}

pub fn mem_mmio_unmap(device_handle: Handle, vm_handle: Handle) void {
    _ = syscall2(.mem_mmio_unmap, device_handle, vm_handle);
}

pub fn proc_create(elf_ptr: u64, elf_len: u64, rights_bits: u64) SystemError!Handle {
    const rc = syscall3(.proc_create, elf_ptr, elf_len, rights_bits);
    if (rc < 0) return mapError(rc);
    return @intCast(rc);
}

pub fn thread_create(entry: *const fn () void, arg: u64, num_stack_pages: u64) SystemError!Handle {
    const rc = syscall3(.thread_create, @intFromPtr(entry), arg, num_stack_pages);
    if (rc < 0) return mapError(rc);
    return @intCast(rc);
}

pub fn thread_exit() noreturn {
    _ = syscall0(.thread_exit);
    unreachable;
}

pub fn thread_yield() void {
    _ = syscall0(.thread_yield);
}

pub fn set_affinity(core_mask: u64) SystemError!void {
    const rc = syscall1(.set_affinity, core_mask);
    if (rc < 0) return mapError(rc);
}

pub fn grant_perm(src_handle: Handle, target_proc_handle: Handle, rights_bits: u64) SystemError!void {
    const rc = syscall3(.grant_perm, src_handle, target_proc_handle, rights_bits);
    if (rc < 0) return mapError(rc);
}

pub fn revoke_perm(handle: Handle) void {
    _ = syscall1(.revoke_perm, handle);
}

pub fn disable_restart() SystemError!void {
    const rc = syscall0(.disable_restart);
    if (rc < 0) return mapError(rc);
}

pub fn futex_wait(addr: *const u64, expected: u64, timeout_ns: u64) SystemError!void {
    const rc = syscall3(.futex_wait, @intFromPtr(addr), expected, timeout_ns);
    if (rc < 0) return mapError(rc);
}

pub fn futex_wake(addr: *const u64, count: u64) SystemError!void {
    const rc = syscall2(.futex_wake, @intFromPtr(addr), count);
    if (rc < 0) return mapError(rc);
}

pub fn clock_gettime() u64 {
    return @intCast(syscall0(.clock_gettime));
}

pub fn ioport_read(device_handle: Handle, port_offset: u64, width: u64) SystemError!u64 {
    const rc = syscall3(.ioport_read, device_handle, port_offset, width);
    if (rc < 0) return mapError(rc);
    return @intCast(rc);
}

pub fn ioport_write(device_handle: Handle, port_offset: u64, width: u64, value: u64) SystemError!void {
    const rc = syscall4(.ioport_write, device_handle, port_offset, width, value);
    if (rc < 0) return mapError(rc);
}

pub fn mem_dma_map(device_handle: Handle, shm_handle: Handle) SystemError!u64 {
    const rc = syscall2(.mem_dma_map, device_handle, shm_handle);
    if (rc < 0) return mapError(rc);
    return @intCast(rc);
}

pub fn mem_dma_unmap(device_handle: Handle, shm_handle: Handle) void {
    _ = syscall2(.mem_dma_unmap, device_handle, shm_handle);
}

pub fn pin_exclusive() SystemError!void {
    const rc = syscall0(.pin_exclusive);
    if (rc < 0) return mapError(rc);
}

pub fn broadcast_syscall(payload: u64) SystemError!void {
    const rc = syscall1(.broadcast, payload);
    if (rc < 0) return mapError(rc);
}

/// Stub — the kernel handles PCI bus master enabling during device init.
pub fn pci_enable_bus_master(device_handle: Handle) void {
    _ = device_handle;
}
