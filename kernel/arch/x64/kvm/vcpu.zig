const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const kvm = zag.arch.x64.kvm;
const interrupts = zag.arch.x64.interrupts;
const vm_hw = zag.arch.x64.vm;
const exit_handler = kvm.exit_handler;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;
const stack_mod = zag.memory.stack;
const thread_mod = zag.sched.thread;
const vm_mod = kvm.vm;

const PAddr = zag.memory.address.PAddr;
const Process = zag.proc.process.Process;
const SlabAllocator = zag.memory.allocators.slab.SlabAllocator;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const Vm = vm_mod.Vm;

/// State of a vCPU. The field is accessed from multiple threads:
/// the vCPU's own thread, `kickRunningVcpus` (walks all vCPUs), the
/// exit handler, and `vm_reply`. All reads/writes must use atomic
/// load/store -- see `loadState`/`storeState` helpers on `VCpu`.
pub const VCpuState = enum(u8) {
    idle,
    running,
    exited,
    waiting_reply,
};

pub const VCpuAllocator = SlabAllocator(VCpu, false, 0, 64, true);

pub var allocator: std.mem.Allocator = undefined;

pub const VCpu = struct {
    thread: *Thread,
    vm: *Vm,
    guest_state: vm_hw.GuestState = .{},
    /// Atomic state. Use `loadState`/`storeState` -- direct `.state = ...`
    /// writes are still allowed inside regions already holding `vm.lock`,
    /// but every other site must go through the atomic helpers.
    state: VCpuState = .idle,
    last_exit_info: vm_hw.VmExitInfo = .{ .unknown = 0 },
    /// Guest FPU/SSE state (FXSAVE format, 512 bytes, 16-byte aligned).
    /// Initialized with default MXCSR=0x1F80, FCW=0x037F.
    guest_fxsave: vm_hw.FxsaveArea align(16) = vm_hw.fxsaveInit(),

    pub inline fn loadState(self: *const VCpu) VCpuState {
        return @atomicLoad(VCpuState, &self.state, .acquire);
    }

    pub inline fn storeState(self: *VCpu, s: VCpuState) void {
        @atomicStore(VCpuState, &self.state, s, .release);
    }
};

/// Create a vCPU: allocate the struct, create a kernel thread, link them.
pub fn create(vm_obj: *Vm) !*VCpu {
    const vcpu_obj = try allocator.create(VCpu);
    errdefer allocator.destroy(vcpu_obj);

    const proc = vm_obj.owner;

    // Allocate a thread from the existing ThreadAllocator
    const thread = try thread_mod.allocator.create(Thread);
    errdefer thread_mod.allocator.destroy(thread);

    thread.* = .{
        .tid = @atomicRmw(u64, &thread_mod.tid_counter, .Add, 1, .monotonic),
        .ctx = undefined,
        .kernel_stack = undefined,
        .user_stack = null,
        .process = proc,
        .state = .blocked, // starts blocked until vm_vcpu_run
    };

    // Allocate kernel stack
    thread.kernel_stack = try stack_mod.createKernel();
    errdefer stack_mod.destroyKernel(thread.kernel_stack, memory_init.kernel_addr_space_root);

    try mapKernelStack(thread.kernel_stack);

    // Set up the thread context with the vCPU entry point
    const kstack_top = zag.memory.address.alignStack(thread.kernel_stack.top);
    thread.ctx = interrupts.prepareThreadContext(kstack_top, null, &vcpuEntryPoint, @intFromPtr(vcpu_obj));

    // Add thread to process thread list
    proc.lock.lock();
    if (proc.num_threads >= Process.MAX_THREADS) {
        proc.lock.unlock();
        return error.MaxThreads;
    }
    thread.slot_index = @intCast(proc.num_threads);
    proc.threads[proc.num_threads] = thread;
    proc.num_threads += 1;
    proc.lock.unlock();

    vcpu_obj.* = .{
        .thread = thread,
        .vm = vm_obj,
    };

    return vcpu_obj;
}

/// Destroy a vCPU: kill its thread and free the struct.
pub fn destroy(vcpu_obj: *VCpu) void {
    const thread = vcpu_obj.thread;

    // Mark thread as exited so scheduler won't run it
    thread.state = .exited;

    // If on a CPU, IPI to force off
    if (sched.coreRunning(thread)) |core_id| {
        arch.smp.triggerSchedulerInterrupt(core_id);
    }

    // Remove from run queues
    sched.removeFromAnyRunQueue(thread);

    allocator.destroy(vcpu_obj);
}

/// Syscall: transition vCPU from idle to running.
pub fn vcpuRun(proc: *Process, thread_handle: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BUSY: i64 = -11;

    const vm_obj = proc.vm orelse return E_INVAL;
    const entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (entry.object != .thread) return E_BADCAP;

    const vcpu_obj = vcpuFromThread(vm_obj, entry.object.thread) orelse return E_BADCAP;

    if (vcpu_obj.loadState() != .idle) return E_BUSY;

    vcpu_obj.storeState(.running);
    const thread = vcpu_obj.thread;
    thread.state = .ready;
    const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
    sched.enqueueOnCore(target_core, thread);

    return 0; // E_OK
}

/// Syscall: set guest state (only when idle).
pub fn vcpuSetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;
    const E_BUSY: i64 = -11;

    const vm_obj = proc.vm orelse return E_INVAL;
    const entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (entry.object != .thread) return E_BADCAP;

    const vcpu_obj = vcpuFromThread(vm_obj, entry.object.thread) orelse return E_BADCAP;

    if (vcpu_obj.loadState() != .idle) return E_BUSY;

    if (state_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(state_ptr)) return E_BADADDR;

    // Read guest state from userspace via physmap, handling cross-page boundaries.
    var buf: [@sizeOf(vm_hw.GuestState)]u8 = undefined;
    if (!readUserStruct(proc, state_ptr, &buf)) return E_BADADDR;
    vcpu_obj.guest_state = std.mem.bytesAsValue(vm_hw.GuestState, &buf).*;
    return 0; // E_OK
}

/// Syscall: get guest state. If running, IPI+suspend+snapshot+resume.
pub fn vcpuGetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;

    const vm_obj = proc.vm orelse return E_INVAL;
    const entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (entry.object != .thread) return E_BADCAP;

    const vcpu_obj = vcpuFromThread(vm_obj, entry.object.thread) orelse return E_BADCAP;

    if (state_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(state_ptr)) return E_BADADDR;

    // Snapshot the state once; avoid racing the vCPU's own writes.
    const state_snapshot = vcpu_obj.loadState();

    // If running, IPI to suspend and snapshot
    if (state_snapshot == .running) {
        const thread = vcpu_obj.thread;
        if (sched.coreRunning(thread)) |core_id| {
            arch.smp.triggerSchedulerInterrupt(core_id);
            // Spin until the thread is off CPU
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        }
    }

    // Write guest state to userspace via physmap, handling cross-page boundaries.
    const src_bytes = std.mem.asBytes(&vcpu_obj.guest_state);
    if (!writeUserStruct(proc, state_ptr, src_bytes)) return E_BADADDR;

    // Resume if it was running
    if (state_snapshot == .running) {
        const thread = vcpu_obj.thread;
        thread.state = .ready;
        const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
        sched.enqueueOnCore(target_core, thread);
    }

    return 0; // E_OK
}

/// Syscall: inject an interrupt into a vCPU.
pub fn vcpuInterrupt(proc: *Process, thread_handle: u64, interrupt_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;

    const vm_obj = proc.vm orelse return E_INVAL;
    const entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (entry.object != .thread) return E_BADCAP;

    const vcpu_obj = vcpuFromThread(vm_obj, entry.object.thread) orelse return E_BADCAP;

    if (interrupt_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(interrupt_ptr)) return E_BADADDR;

    // Read interrupt from userspace via physmap, handling cross-page boundaries.
    var int_buf: [@sizeOf(vm_hw.GuestInterrupt)]u8 = undefined;
    if (!readUserStruct(proc, interrupt_ptr, &int_buf)) return E_BADADDR;
    const interrupt = std.mem.bytesAsValue(vm_hw.GuestInterrupt, &int_buf).*;

    // Reject reserved architectural exception vectors 0-31 (Intel SDM Vol 3A,
    // §6.3.1 "External Interrupts" and Table 6-1). External interrupts must
    // use vectors >= 32; injecting 0-15 (faults) or 16-31 (reserved) via the
    // VM-entry event-injection path (bypassing the LAPIC) would let an
    // attacker VMM corrupt guest exception handling by writing an illegal
    // vector directly to VMCS VM_ENTRY_INTR_INFO.
    if (interrupt.vector < 32) return E_INVAL;

    if (vcpu_obj.loadState() == .running) {
        const thread = vcpu_obj.thread;
        // IPI to suspend
        if (sched.coreRunning(thread)) |core_id| {
            arch.smp.triggerSchedulerInterrupt(core_id);
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        }
        // If the vCPU entry loop (or a prior injection) already queued a
        // vector in pending_eventinj, don't clobber it. Route this vector
        // through the LAPIC IRR so the entry loop can pick it up next time.
        if (vcpu_obj.guest_state.pending_eventinj != 0) {
            vm_obj.injectExternal(interrupt.vector);
        } else {
            arch.vm.vmInjectInterrupt(&vcpu_obj.guest_state, interrupt);
        }
        thread.state = .ready;
        const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
        sched.enqueueOnCore(target_core, thread);
    } else {
        // Not running — write pending interrupt into arch state
        if (vcpu_obj.guest_state.pending_eventinj != 0) {
            vm_obj.injectExternal(interrupt.vector);
        } else {
            arch.vm.vmInjectInterrupt(&vcpu_obj.guest_state, interrupt);
        }
    }

    return 0; // E_OK
}

/// Find the VCpu that owns a given thread within a VM.
pub fn vcpuFromThread(vm_obj: *Vm, thread: *Thread) ?*VCpu {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus]) |v| {
        if (v.thread == thread) return v;
    }
    return null;
}

/// The kernel-managed vCPU thread entry point.
/// When scheduled, enters guest mode via vm_hw.vmResume() in a loop.
fn vcpuEntryPoint() void {
    // Look up our VCpu by finding the current thread in the VM's vcpu array.
    const thread = sched.currentThread().?;
    const vm_obj = thread.process.vm.?;
    const vcpu_obj = vcpuFromThread(vm_obj, thread).?;

    var last_tsc: u64 = arch.time.readTimestamp();

    while (true) {
        if (vcpu_obj.loadState() != .running) {
            // Block until the VMM resumes us via vm_reply.
            thread.state = .blocked;
            arch.interrupts.enableInterrupts();
            sched.yield();
            last_tsc = arch.time.readTimestamp();
            continue;
        }

        // Tick interrupt-controller timers with elapsed nanoseconds before
        // each VMRUN. TSC ticks at ~1 GHz on most hardware; treat 1 tick = 1 ns.
        const now_tsc = arch.time.readTimestamp();
        const elapsed_ns = now_tsc -% last_tsc;
        last_tsc = now_tsc;
        vm_obj.tickInterruptControllers(elapsed_ns);

        // Inject any pending deliverable interrupt vector from the kernel
        // interrupt controllers (gated on guest IF, no prior EVENTINJ).
        vm_obj.deliverPendingInterrupts(&vcpu_obj.guest_state);

        // Enter guest mode
        const vm_structures = vm_obj.arch_structures;
        const exit_info = vm_hw.vmResume(&vcpu_obj.guest_state, vm_structures, &vcpu_obj.guest_fxsave);

        // Handle the exit
        vcpu_obj.last_exit_info = exit_info;
        exit_handler.handleExit(vcpu_obj, exit_info);
    }
}

/// Verify [user_va, user_va+len) is entirely inside the user partition.
/// Catches length overflow and the "last byte of user page, rest spills
/// into kernel partition" case that the per-page walk would otherwise
/// advance into blindly.
fn checkUserRange(user_va: u64, len: usize) bool {
    const end = std.math.add(u64, user_va, len) catch return false;
    if (!zag.memory.address.AddrSpacePartition.user.contains(user_va)) return false;
    if (end != user_va and !zag.memory.address.AddrSpacePartition.user.contains(end - 1)) return false;
    return true;
}

/// Read a struct from userspace into a kernel buffer, handling cross-page boundaries.
/// Pre-faults pages and resolves each page's physical address independently.
fn readUserStruct(proc: *Process, user_va: u64, buf: []u8) bool {
    if (!checkUserRange(user_va, buf.len)) return false;
    var remaining: usize = buf.len;
    var dst_off: usize = 0;
    var src_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = src_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(src_va), false, false) catch return false;
        const page_paddr = arch.paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        @memcpy(buf[dst_off..][0..chunk], src[0..chunk]);
        dst_off += chunk;
        src_va += chunk;
        remaining -= chunk;
    }
    return true;
}

/// Write a kernel buffer to userspace, handling cross-page boundaries.
/// Pre-faults pages and resolves each page's physical address independently.
fn writeUserStruct(proc: *Process, user_va: u64, data: []const u8) bool {
    if (!checkUserRange(user_va, data.len)) return false;
    var remaining: usize = data.len;
    var src_off: usize = 0;
    var dst_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = dst_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(dst_va), true, false) catch return false;
        const page_paddr = arch.paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        @memcpy(dst[0..chunk], data[src_off..][0..chunk]);
        src_off += chunk;
        dst_va += chunk;
        remaining -= chunk;
    }
    return true;
}

fn mapKernelStack(stack: zag.memory.stack.Stack) !void {
    const pmm_iface = pmm.global_pmm.?.allocator();
    var page_addr = stack.base.addr;
    while (page_addr < stack.top.addr) {
        const kpage = try pmm_iface.create(paging.PageMem(.page4k));
        @memset(std.mem.asBytes(kpage), 0);
        const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
        try arch.paging.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), .{
            .write_perm = .write,
            .execute_perm = .no_execute,
            .cache_perm = .write_back,
            .global_perm = .global,
            .privilege_perm = .kernel,
        });
        page_addr += paging.PAGE4K;
    }
}
