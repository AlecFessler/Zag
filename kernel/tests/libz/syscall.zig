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
    revoke_perm,
    disable_restart,
    futex_wait,
    futex_wake,
    clock_gettime,
    ioport_read,
    ioport_write,
    dma_map,
    dma_unmap,
    pin_exclusive,
    ipc_send,
    ipc_call,
    ipc_recv,
    ipc_reply,
};

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
    return syscall2(.shm_create, size, 0);
}

pub fn shm_create_with_rights(size: u64, rights: u64) i64 {
    return syscall2(.shm_create, size, rights);
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

pub fn revoke_perm(handle: u64) i64 {
    return syscall1(.revoke_perm, handle);
}

pub fn disable_restart() i64 {
    return syscall0(.disable_restart);
}

pub fn futex_wait(addr: *const u64, expected: u64, timeout_ns: u64) i64 {
    return syscall3(.futex_wait, @intFromPtr(addr), expected, timeout_ns);
}

pub fn futex_wake(addr: *const u64, count: u64) i64 {
    return syscall2(.futex_wake, @intFromPtr(addr), count);
}

pub fn clock_gettime() i64 {
    return syscall0(.clock_gettime);
}

pub fn ioport_read(device_handle: u64, port_offset: u64, width: u64) i64 {
    return syscall3(.ioport_read, device_handle, port_offset, width);
}

pub fn ioport_write(device_handle: u64, port_offset: u64, width: u64, value: u64) i64 {
    return syscall4(.ioport_write, device_handle, port_offset, width, value);
}

pub fn dma_map(device_handle: u64, shm_handle: u64) i64 {
    return syscall2(.dma_map, device_handle, shm_handle);
}

pub fn dma_unmap(device_handle: u64, shm_handle: u64) i64 {
    return syscall2(.dma_unmap, device_handle, shm_handle);
}

pub fn pin_exclusive() i64 {
    return syscall0(.pin_exclusive);
}

// --- IPC Message Passing ---

pub const IpcMessage = struct {
    words: [5]u64 = .{0} ** 5,
    word_count: u3 = 0,
    from_call: bool = false,
};

pub fn ipc_send(target_handle: u64, words: []const u64) i64 {
    return ipc_send_ex(target_handle, words, false);
}

pub fn ipc_send_cap(target_handle: u64, words: []const u64) i64 {
    return ipc_send_ex(target_handle, words, true);
}

fn ipc_send_ex(target_handle: u64, words: []const u64, cap_transfer: bool) i64 {
    var w: [5]u64 = .{0} ** 5;
    const count: u3 = @intCast(@min(words.len, 5));
    for (0..count) |i| w[i] = words[i];
    const meta: u64 = @as(u64, count) | (if (cap_transfer) @as(u64, 0x8) else 0);

    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(SyscallNum.ipc_send)),
          [tgt] "{r13}" (target_handle),
          [m] "{r14}" (meta),
          [w0] "{rdi}" (w[0]),
          [w1] "{rsi}" (w[1]),
          [w2] "{rdx}" (w[2]),
          [w3] "{r8}" (w[3]),
          [w4] "{r9}" (w[4]),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

pub fn ipc_call(target_handle: u64, words: []const u64, reply: *IpcMessage) i64 {
    return ipc_call_ex(target_handle, words, false, reply);
}

pub fn ipc_call_cap(target_handle: u64, words: []const u64, reply: *IpcMessage) i64 {
    return ipc_call_ex(target_handle, words, true, reply);
}

fn ipc_call_ex(target_handle: u64, words: []const u64, cap_transfer: bool, reply: *IpcMessage) i64 {
    var w: [5]u64 = .{0} ** 5;
    const count: u3 = @intCast(@min(words.len, 5));
    for (0..count) |i| w[i] = words[i];
    const meta: u64 = @as(u64, count) | (if (cap_transfer) @as(u64, 0x8) else 0);

    var r_rdi: u64 = undefined;
    var r_rsi: u64 = undefined;
    var r_rdx: u64 = undefined;
    var r_r8: u64 = undefined;
    var r_r9: u64 = undefined;
    var r_r14: u64 = undefined;

    const ret = asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
          [o0] "={rdi}" (r_rdi),
          [o1] "={rsi}" (r_rsi),
          [o2] "={rdx}" (r_rdx),
          [o3] "={r8}" (r_r8),
          [o4] "={r9}" (r_r9),
          [om] "={r14}" (r_r14),
        : [num] "{rax}" (@intFromEnum(SyscallNum.ipc_call)),
          [tgt] "{r13}" (target_handle),
          [m] "{r14}" (meta),
          [w0] "{rdi}" (w[0]),
          [w1] "{rsi}" (w[1]),
          [w2] "{rdx}" (w[2]),
          [w3] "{r8}" (w[3]),
          [w4] "{r9}" (w[4]),
        : .{ .rcx = true, .r11 = true, .memory = true });

    reply.words = .{ r_rdi, r_rsi, r_rdx, r_r8, r_r9 };
    reply.word_count = @truncate((r_r14 >> 1) & 0x7);
    reply.from_call = (r_r14 & 1) != 0;
    return ret;
}

pub fn ipc_recv(blocking: bool, msg: *IpcMessage) i64 {
    const meta: u64 = if (blocking) 0x2 else 0;

    var r_rdi: u64 = undefined;
    var r_rsi: u64 = undefined;
    var r_rdx: u64 = undefined;
    var r_r8: u64 = undefined;
    var r_r9: u64 = undefined;
    var r_r14: u64 = undefined;

    const ret = asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
          [o0] "={rdi}" (r_rdi),
          [o1] "={rsi}" (r_rsi),
          [o2] "={rdx}" (r_rdx),
          [o3] "={r8}" (r_r8),
          [o4] "={r9}" (r_r9),
          [om] "={r14}" (r_r14),
        : [num] "{rax}" (@intFromEnum(SyscallNum.ipc_recv)),
          [m] "{r14}" (meta),
        : .{ .rcx = true, .r11 = true, .r13 = true, .memory = true });

    msg.words = .{ r_rdi, r_rsi, r_rdx, r_r8, r_r9 };
    msg.word_count = @truncate((r_r14 >> 1) & 0x7);
    msg.from_call = (r_r14 & 1) != 0;
    return ret;
}

pub fn ipc_reply(words: []const u64) i64 {
    return ipc_reply_ex(words, false, false);
}

pub fn ipc_reply_recv(words: []const u64, blocking: bool, msg: *IpcMessage) i64 {
    var w: [5]u64 = .{0} ** 5;
    const count: u3 = @intCast(@min(words.len, 5));
    for (0..count) |i| w[i] = words[i];
    const meta: u64 = @as(u64, count) << 2 | 0x1 | (if (blocking) @as(u64, 0x2) else 0);

    var r_rdi: u64 = undefined;
    var r_rsi: u64 = undefined;
    var r_rdx: u64 = undefined;
    var r_r8: u64 = undefined;
    var r_r9: u64 = undefined;
    var r_r14: u64 = undefined;

    const ret = asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
          [o0] "={rdi}" (r_rdi),
          [o1] "={rsi}" (r_rsi),
          [o2] "={rdx}" (r_rdx),
          [o3] "={r8}" (r_r8),
          [o4] "={r9}" (r_r9),
          [om] "={r14}" (r_r14),
        : [num] "{rax}" (@intFromEnum(SyscallNum.ipc_reply)),
          [m] "{r14}" (meta),
          [w0] "{rdi}" (w[0]),
          [w1] "{rsi}" (w[1]),
          [w2] "{rdx}" (w[2]),
          [w3] "{r8}" (w[3]),
          [w4] "{r9}" (w[4]),
        : .{ .rcx = true, .r11 = true, .r13 = true, .memory = true });

    msg.words = .{ r_rdi, r_rsi, r_rdx, r_r8, r_r9 };
    msg.word_count = @truncate((r_r14 >> 1) & 0x7);
    msg.from_call = (r_r14 & 1) != 0;
    return ret;
}

fn ipc_reply_ex(words: []const u64, atomic_recv: bool, recv_blocking: bool) i64 {
    var w: [5]u64 = .{0} ** 5;
    const count: u3 = @intCast(@min(words.len, 5));
    for (0..count) |i| w[i] = words[i];
    const meta: u64 = @as(u64, count) << 2 |
        (if (atomic_recv) @as(u64, 0x1) else 0) |
        (if (recv_blocking) @as(u64, 0x2) else 0);

    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(SyscallNum.ipc_reply)),
          [m] "{r14}" (meta),
          [w0] "{rdi}" (w[0]),
          [w1] "{rsi}" (w[1]),
          [w2] "{rdx}" (w[2]),
          [w3] "{r8}" (w[3]),
          [w4] "{r9}" (w[4]),
        : .{ .rcx = true, .r11 = true, .r13 = true, .memory = true });
}
