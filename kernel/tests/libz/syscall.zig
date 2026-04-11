const perms = @import("perms.zig");

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
    set_priority,
    ipc_send,
    ipc_call,
    ipc_recv,
    ipc_reply,
    shutdown,
    thread_self,
    thread_suspend,
    thread_resume,
    thread_kill,
    fault_recv,
    fault_reply,
    fault_read_mem,
    fault_write_mem,
    fault_set_thread_mode,
    vm_create,
    vm_destroy,
    guest_map,
    vm_recv,
    vm_reply,
    vcpu_set_state,
    vcpu_get_state,
    vcpu_run,
    vcpu_interrupt,
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

fn syscall5(num: SyscallNum, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    return asm volatile (
        \\int $0x80
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r10}" (a3),
          [a4] "{r8}" (a4),
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

pub fn write_raw(ptr: u64, len: u64) i64 {
    return syscall2(.write, ptr, len);
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
    return proc_create_with_opts(elf_ptr, elf_len, rights_bits, perms.ThreadHandleRights.full.bits(), PRIORITY_NORMAL);
}

pub fn proc_create_with_thread_rights(elf_ptr: u64, elf_len: u64, rights_bits: u64, thread_rights: u64) i64 {
    return proc_create_with_opts(elf_ptr, elf_len, rights_bits, thread_rights, PRIORITY_NORMAL);
}

pub fn proc_create_with_opts(elf_ptr: u64, elf_len: u64, rights_bits: u64, thread_rights: u64, max_priority: u64) i64 {
    return syscall5(.proc_create, elf_ptr, elf_len, rights_bits, thread_rights, max_priority);
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

pub fn thread_yield_raw() i64 {
    return syscall0(.thread_yield);
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

pub const PRIORITY_IDLE: u64 = 0;
pub const PRIORITY_NORMAL: u64 = 1;
pub const PRIORITY_HIGH: u64 = 2;
pub const PRIORITY_REALTIME: u64 = 3;
pub const PRIORITY_PINNED: u64 = 4;

pub fn set_priority(priority: u64) i64 {
    return syscall1(.set_priority, priority);
}

pub fn shutdown() noreturn {
    _ = syscall0(.shutdown);
    unreachable;
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
    return ipc_reply_ex(words, false, false, false);
}

pub fn ipc_reply_cap(words: []const u64) i64 {
    return ipc_reply_ex(words, false, false, true);
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

// --- New Thread/Fault Syscalls ---

pub fn thread_self() i64 {
    return syscall0(.thread_self);
}

pub fn thread_suspend(thread_handle: u64) i64 {
    return syscall1(.thread_suspend, thread_handle);
}

pub fn thread_resume(thread_handle: u64) i64 {
    return syscall1(.thread_resume, thread_handle);
}

pub fn thread_kill(thread_handle: u64) i64 {
    return syscall1(.thread_kill, thread_handle);
}

pub fn fault_recv(buf_ptr: u64, blocking: u64) i64 {
    return syscall2(.fault_recv, buf_ptr, blocking);
}

pub fn fault_reply_action(token: u64, action: u64, modified_regs_ptr: u64) i64 {
    return syscall3(.fault_reply, token, action, modified_regs_ptr);
}

pub fn fault_reply_simple(token: u64, action: u64) i64 {
    return syscall3(.fault_reply, token, action, 0);
}

/// Invoke `fault_reply` with explicit `flags` in r14 (e.g. FAULT_EXCLUDE_NEXT,
/// FAULT_EXCLUDE_PERMANENT). `modified_regs_ptr` is passed via rdx.
pub fn fault_reply_flags(token: u64, action: u64, modified_regs_ptr: u64, flags: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(SyscallNum.fault_reply)),
          [a0] "{rdi}" (token),
          [a1] "{rsi}" (action),
          [a2] "{rdx}" (modified_regs_ptr),
          [f] "{r14}" (flags),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

pub fn fault_read_mem(proc_handle: u64, vaddr: u64, buf_ptr: u64, len: u64) i64 {
    return syscall4(.fault_read_mem, proc_handle, vaddr, buf_ptr, len);
}

pub fn fault_write_mem(proc_handle: u64, vaddr: u64, buf_ptr: u64, len: u64) i64 {
    return syscall4(.fault_write_mem, proc_handle, vaddr, buf_ptr, len);
}

pub fn fault_set_thread_mode(thread_handle: u64, mode: u64) i64 {
    return syscall2(.fault_set_thread_mode, thread_handle, mode);
}

// --- VM / vCPU Syscalls ---

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

pub fn vm_create(vcpu_count: u64, policy_ptr: u64) i64 {
    return syscall2(.vm_create, vcpu_count, policy_ptr);
}

pub fn vm_destroy() i64 {
    return syscall0(.vm_destroy);
}

pub fn guest_map(host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    return syscall4(.guest_map, host_vaddr, guest_addr, size, rights);
}

pub fn vm_recv(buf_ptr: u64, blocking: u64) i64 {
    return syscall2(.vm_recv, buf_ptr, blocking);
}

pub fn vm_reply_action(exit_token: u64, action_ptr: u64) i64 {
    return syscall2(.vm_reply, exit_token, action_ptr);
}

pub fn vcpu_set_state(thread_handle: u64, guest_state_ptr: u64) i64 {
    return syscall2(.vcpu_set_state, thread_handle, guest_state_ptr);
}

pub fn vcpu_get_state(thread_handle: u64, guest_state_ptr: u64) i64 {
    return syscall2(.vcpu_get_state, thread_handle, guest_state_ptr);
}

pub fn vcpu_run(thread_handle: u64) i64 {
    return syscall1(.vcpu_run, thread_handle);
}

pub fn vcpu_interrupt(thread_handle: u64, interrupt_ptr: u64) i64 {
    return syscall2(.vcpu_interrupt, thread_handle, interrupt_ptr);
}

pub const FAULT_KILL: u64 = 0;
pub const FAULT_RESUME: u64 = 1;
pub const FAULT_RESUME_MODIFIED: u64 = 2;

pub const FAULT_MODE_STOP_ALL: u64 = 0;
pub const FAULT_MODE_EXCLUDE_NEXT: u64 = 1;
pub const FAULT_MODE_EXCLUDE_PERMANENT: u64 = 2;

pub const FaultMessage = extern struct {
    process_handle: u64,
    thread_handle: u64,
    fault_reason: u8,
    _pad: [7]u8,
    fault_addr: u64,
    // SavedRegs area: kernel writes rip first.
    rip: u64,
    _regs_rest: [136]u8,
};

fn ipc_reply_ex(words: []const u64, atomic_recv: bool, recv_blocking: bool, cap_transfer: bool) i64 {
    var w: [5]u64 = .{0} ** 5;
    const count: u3 = @intCast(@min(words.len, 5));
    for (0..count) |i| w[i] = words[i];
    const meta: u64 = @as(u64, count) << 2 |
        (if (atomic_recv) @as(u64, 0x1) else 0) |
        (if (recv_blocking) @as(u64, 0x2) else 0) |
        (if (cap_transfer) @as(u64, 0x20) else 0);

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
