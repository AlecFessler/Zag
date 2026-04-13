const perms = @import("perms.zig");

pub const PAGE4K: u64 = 4096;

pub const SyscallResult2 = struct {
    val: i64,
    val2: u64,
};

pub const SyscallNum = enum(u64) {
    write,
    mem_reserve,
    mem_perms,
    mem_shm_create,
    mem_shm_map,
    mem_unmap,
    mem_mmio_map,
    _mem_mmio_unmap_removed,
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
    mem_dma_map,
    mem_dma_unmap,
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
    vm_guest_map,
    vm_recv,
    vm_reply,
    vm_vcpu_set_state,
    vm_vcpu_get_state,
    vm_vcpu_run,
    vm_vcpu_interrupt,
    vm_msr_passthrough,
    vm_ioapic_assert_irq,
    vm_ioapic_deassert_irq,
    pmu_info,
    pmu_start,
    pmu_read,
    pmu_reset,
    pmu_stop,
    sys_info,
    clock_getwall,
    clock_setwall,
    getrandom,
    notify_wait,
    irq_ack,
    sys_power,
    sys_cpu_power,
    thread_unpin,
};

fn syscall0(num: SyscallNum) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
}

fn syscall1(num: SyscallNum, a0: u64) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
}

fn syscall2(num: SyscallNum, a0: u64, a1: u64) i64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
}

fn syscall3(num: SyscallNum, a0: u64, a1: u64, a2: u64) i64 {
    return asm volatile (
        \\syscall
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(num)),
          [a0] "{rdi}" (a0),
          [a1] "{rsi}" (a1),
          [a2] "{rdx}" (a2),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
}

fn syscall4(num: SyscallNum, a0: u64, a1: u64, a2: u64, a3: u64) i64 {
    return asm volatile (
        \\syscall
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
        \\syscall
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
    const val = asm volatile ("syscall"
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

pub fn mem_reserve(hint: u64, size: u64, rights_bits: u64) SyscallResult2 {
    return syscall3_2(.mem_reserve, hint, size, rights_bits);
}

pub fn mem_perms(vm_handle: u64, offset: u64, size: u64, rights_bits: u64) i64 {
    return syscall4(.mem_perms, vm_handle, offset, size, rights_bits);
}

pub fn mem_shm_create(size: u64) i64 {
    return syscall2(.mem_shm_create, size, 0);
}

pub fn shm_create_with_rights(size: u64, rights: u64) i64 {
    return syscall2(.mem_shm_create, size, rights);
}

pub fn mem_shm_map(shm_handle: u64, vm_handle: u64, offset: u64) i64 {
    return syscall3(.mem_shm_map, shm_handle, vm_handle, offset);
}

pub fn mem_unmap(vm_handle: u64, offset: u64, size: u64) i64 {
    return syscall3(.mem_unmap, vm_handle, offset, size);
}

pub fn mem_mmio_map(device_handle: u64, vm_handle: u64, offset: u64) i64 {
    return syscall3(.mem_mmio_map, device_handle, vm_handle, offset);
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

pub fn mem_dma_map(device_handle: u64, shm_handle: u64) i64 {
    return syscall2(.mem_dma_map, device_handle, shm_handle);
}

pub fn mem_dma_unmap(device_handle: u64, shm_handle: u64) i64 {
    return syscall2(.mem_dma_unmap, device_handle, shm_handle);
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

    return asm volatile ("syscall"
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

    const ret = asm volatile ("syscall"
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

    const ret = asm volatile ("syscall"
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

    const ret = asm volatile ("syscall"
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

pub fn thread_unpin(thread_handle: u64) i64 {
    return syscall1(.thread_unpin, thread_handle);
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
    return asm volatile ("syscall"
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

/// Deprecated: always returns E_INVAL. Use revoke_vm() instead.
pub fn vm_destroy() i64 {
    return syscall0(.vm_destroy);
}

pub fn vm_guest_map(vm_handle_arg: u64, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    return syscall5(.vm_guest_map, vm_handle_arg, host_vaddr, guest_addr, size, rights);
}

pub fn vm_recv(vm_handle_arg: u64, buf_ptr: u64, blocking: u64) i64 {
    return syscall3(.vm_recv, vm_handle_arg, buf_ptr, blocking);
}

pub fn vm_reply_action(vm_handle_arg: u64, exit_token: u64, action_ptr: u64) i64 {
    return syscall3(.vm_reply, vm_handle_arg, exit_token, action_ptr);
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

pub fn vm_msr_passthrough(vm_handle_arg: u64, msr_num: u64, allow_read: u64, allow_write: u64) i64 {
    return syscall4(.vm_msr_passthrough, vm_handle_arg, msr_num, allow_read, allow_write);
}

pub fn vm_ioapic_assert_irq(vm_handle_arg: u64, irq_num: u64) i64 {
    return syscall2(.vm_ioapic_assert_irq, vm_handle_arg, irq_num);
}

pub fn vm_ioapic_deassert_irq(vm_handle_arg: u64, irq_num: u64) i64 {
    return syscall2(.vm_ioapic_deassert_irq, vm_handle_arg, irq_num);
}

pub fn revoke_vm(vm_handle_arg: u64) i64 {
    return syscall1(.revoke_perm, vm_handle_arg);
}

// --- Performance Monitoring Unit (§2.14, §4.50–§4.54) ---

pub const PMU_MAX_COUNTERS: usize = 8;

pub const PmuEvent = enum(u8) {
    cycles = 0,
    instructions = 1,
    cache_references = 2,
    cache_misses = 3,
    branch_instructions = 4,
    branch_misses = 5,
    bus_cycles = 6,
    stalled_cycles_frontend = 7,
    stalled_cycles_backend = 8,
    _,
};

/// Configures one PMU counter. `has_threshold == false` means precise counting
/// (no overflow fault); `has_threshold == true` selects sample-based profiling
/// at `overflow_threshold` events. Matches the kernel's canonical 24-byte
/// extern layout (see kernel/sched/pmu.zig).
pub const PmuCounterConfig = extern struct {
    event: PmuEvent,
    _pad: [7]u8 = .{0} ** 7,
    has_threshold: bool,
    _pad2: [7]u8 = .{0} ** 7,
    overflow_threshold: u64,
};

pub const PmuInfo = extern struct {
    num_counters: u8,
    overflow_support: bool,
    _pad: [6]u8 = .{0} ** 6,
    supported_events: u64,
};

pub const PmuSample = extern struct {
    counters: [PMU_MAX_COUNTERS]u64 = .{0} ** PMU_MAX_COUNTERS,
    timestamp: u64 = 0,
};

pub const FAULT_REASON_PMU_OVERFLOW: u8 = 15;

pub fn pmu_info(info_ptr: u64) i64 {
    return syscall1(.pmu_info, info_ptr);
}

pub fn pmu_start(thread_handle: u64, configs_ptr: u64, count: u64) i64 {
    return syscall3(.pmu_start, thread_handle, configs_ptr, count);
}

pub fn pmu_read(thread_handle: u64, sample_ptr: u64) i64 {
    return syscall2(.pmu_read, thread_handle, sample_ptr);
}

pub fn pmu_reset(thread_handle: u64, configs_ptr: u64, count: u64) i64 {
    return syscall3(.pmu_reset, thread_handle, configs_ptr, count);
}

pub fn pmu_stop(thread_handle: u64) i64 {
    return syscall1(.pmu_stop, thread_handle);
}

// --- System Information (§2.15, §4.55) ---

/// Matches §5 "Max CPU cores" and "Max `SysInfo.core_count`". Tests use this
/// as a worst-case bound when sizing stack-resident `CoreInfo` arrays without
/// having to first poll `sys_info` for the actual count.
pub const MAX_CPU_CORES: usize = 64;

/// System-wide static and dynamic properties returned by `sys_info` in its
/// `info_ptr` output. Matches the canonical extern layout defined in §2.15 of
/// the spec.
pub const SysInfo = extern struct {
    core_count: u64,
    mem_total: u64,
    mem_free: u64,
};

/// Per-core dynamic properties returned by `sys_info` in its `cores_ptr`
/// output, one entry per core indexed by core ID. Matches §2.15. The trailing
/// explicit padding brings the struct to 8-byte alignment so a `[N]CoreInfo`
/// array lays out predictably across the syscall boundary.
pub const CoreInfo = extern struct {
    idle_ns: u64,
    busy_ns: u64,
    freq_hz: u64,
    temp_mc: u32,
    c_state: u8,
    _pad: [3]u8 = .{0} ** 3,
};

// ABI guard against drift from the kernel side, which asserts the same
// sizes in `kernel/sched/sysinfo.zig`. The struct layout is part of the
// observable §2.15 contract, so any change here must be matched on both
// sides.
comptime {
    if (@sizeOf(SysInfo) != 24) @compileError("SysInfo must be 24 bytes (§2.15)");
    if (@sizeOf(CoreInfo) != 32) @compileError("CoreInfo must be 32 bytes (§2.15)");
}

/// Invokes `sys_info(info_ptr, cores_ptr)`. Pass `0` for `cores_ptr` to read
/// `SysInfo` without touching per-core scheduler accounting (§2.15, §4.55.4).
pub fn sys_info(info_ptr: u64, cores_ptr: u64) i64 {
    return syscall2(.sys_info, info_ptr, cores_ptr);
}

/// Returns the lowest-indexed event variant whose bit is set in
/// `info.supported_events`, or null if no defined variants are supported on
/// this hardware. Test helpers call this and skip the positive path when it
/// returns null, so the same binary passes on both counter-capable hardware
/// and stubbed/no-PMU rigs (see §2.14 and §4.50–§4.54).
pub fn pickSupportedEvent(info: PmuInfo) ?PmuEvent {
    inline for (@typeInfo(PmuEvent).@"enum".fields) |f| {
        const bit = @as(u64, 1) << f.value;
        if ((info.supported_events & bit) != 0) return @enumFromInt(f.value);
    }
    return null;
}

// --- Wall Clock (§2.16, §4.56–§4.57) ---

pub fn clock_getwall() i64 {
    return syscall0(.clock_getwall);
}

pub fn clock_setwall(nanos: u64) i64 {
    return syscall1(.clock_setwall, nanos);
}

// --- Randomness (§2.17, §4.58) ---

pub fn getrandom(buf: [*]u8, len: u64) i64 {
    return syscall2(.getrandom, @intFromPtr(buf), len);
}

pub fn getrandom_raw(buf_addr: u64, len: u64) i64 {
    return syscall2(.getrandom, buf_addr, len);
}

// --- IRQ Notifications (§2.18, §4.59–§4.60) ---

pub fn notify_wait(timeout_ns: u64) i64 {
    return syscall1(.notify_wait, timeout_ns);
}

pub fn irq_ack(handle: u64) i64 {
    return syscall1(.irq_ack, handle);
}

// --- Power Control (§2.19, §4.61–§4.62) ---

pub const POWER_SHUTDOWN: u64 = 0;
pub const POWER_REBOOT: u64 = 1;
pub const POWER_SLEEP: u64 = 2;
pub const POWER_HIBERNATE: u64 = 3;
pub const POWER_SCREEN_OFF: u64 = 4;

pub const CPU_POWER_SET_FREQ: u64 = 0;
pub const CPU_POWER_SET_IDLE: u64 = 1;

pub fn sys_power(action: u64) i64 {
    return syscall1(.sys_power, action);
}

pub fn sys_cpu_power(action: u64, value: u64) i64 {
    return syscall2(.sys_cpu_power, action, value);
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

    return asm volatile ("syscall"
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
