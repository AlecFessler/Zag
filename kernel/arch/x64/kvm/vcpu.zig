const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch_paging = zag.arch.x64.paging;
const cpu = zag.arch.x64.cpu;
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

const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const Process = zag.proc.process.Process;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
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

pub const VCpuAllocator = SecureSlab(VCpu, 256);

pub var slab_instance: VCpuAllocator = undefined;

pub const VCpu = struct {
    _gen_lock: GenLock = .{},
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

    /// Advance guest RIP by `bytes`. Wrapping add matches the arithmetic the
    /// callers used inline and keeps an out-of-band guest RIP (e.g. a guest
    /// jumping to near the top of the 64-bit address space) from panicking
    /// a safety-checked kernel build on the post-instruction advance.
    pub inline fn advanceRip(self: *VCpu, bytes: u8) void {
        self.guest_state.rip +%= bytes;
    }

    /// Write the CPUID response registers into guest state and advance RIP
    /// past the CPUID instruction. All inline CPUID exit paths route through
    /// here so guest-state writes stay local to VCpu.
    pub inline fn respondCpuid(
        self: *VCpu,
        rax_value: u64,
        rbx_value: u64,
        rcx_value: u64,
        rdx_value: u64,
        advance: u8,
    ) void {
        self.guest_state.rax = rax_value;
        self.guest_state.rbx = rbx_value;
        self.guest_state.rcx = rcx_value;
        self.guest_state.rdx = rdx_value;
        self.advanceRip(advance);
    }
};

/// Create a vCPU: allocate the struct, create a kernel thread, link them.
pub fn create(vm_obj: *Vm) !*VCpu {
    const vcpu_alloc = try slab_instance.create();
    const vcpu_obj = vcpu_alloc.ptr;
    errdefer slab_instance.destroy(vcpu_obj, vcpu_alloc.gen) catch unreachable;

    const proc = vm_obj.owner;

    // Allocate a thread from the existing ThreadAllocator
    const thread_alloc = try thread_mod.slab_instance.create();
    const thread = thread_alloc.ptr;
    errdefer thread_mod.slab_instance.destroy(thread, thread_alloc.gen) catch unreachable;

    // Field-by-field init preserves `thread._gen_lock` set by the slab
    // allocator. A `.* = .{...}` would zero it.
    thread.tid = @atomicRmw(u64, &thread_mod.tid_counter, .Add, 1, .monotonic);
    thread.ctx = undefined;
    thread.kernel_stack = undefined;
    thread.user_stack = null;
    thread.process = proc;
    thread.next = null;
    thread.priority = .normal;
    thread.pre_pin_priority = .normal;
    thread.pre_pin_affinity = null;
    thread.core_affinity = null;
    thread.state = .blocked; // starts blocked until vm_vcpu_run
    thread.on_cpu = std.atomic.Value(bool).init(false);
    thread.pinned_exclusive = false;
    thread.futex_deadline_ns = 0;
    thread.futex_paddr = PAddr.fromInt(0);
    thread.futex_wake_index = 0;
    thread.futex_paddrs = [_]PAddr{PAddr.fromInt(0)} ** 64;
    thread.futex_bucket_count = 0;
    thread.ipc_server = null;
    thread.slot_index = 0;
    thread.fault_reason = .none;
    thread.fault_addr = 0;
    thread.fault_rip = 0;
    thread.fault_user_ctx = null;
    thread.pmu_state = null;
    thread.fpu_state = [_]u8{0} ** 576;
    thread.last_fpu_core = null;
    thread.handle_refcount = std.atomic.Value(u32).init(0);
    thread.teardown_done = false;

    // Allocate kernel stack
    thread.kernel_stack = try stack_mod.createKernel();
    errdefer stack_mod.destroyKernel(thread.kernel_stack, memory_init.kernel_addr_space_root);

    try mapKernelStack(thread.kernel_stack);

    // Set up the thread context with the vCPU entry point
    const kstack_top = zag.memory.address.alignStack(thread.kernel_stack.top);
    thread.ctx = interrupts.prepareThreadContext(kstack_top, null, &vcpuEntryPoint, @intFromPtr(vcpu_obj));

    // Add thread to process thread list
    proc._gen_lock.lock();
    if (proc.num_threads >= Process.MAX_THREADS) {
        proc._gen_lock.unlock();
        return error.MaxThreads;
    }
    thread.slot_index = @intCast(proc.num_threads);
    proc.threads[proc.num_threads] = thread;
    proc.num_threads += 1;
    proc._gen_lock.unlock();

    // Field-by-field to preserve `vcpu_obj._gen_lock`.
    vcpu_obj.thread = thread;
    vcpu_obj.vm = vm_obj;
    vcpu_obj.guest_state = .{};
    vcpu_obj.state = .idle;
    vcpu_obj.last_exit_info = .{ .unknown = 0 };
    vcpu_obj.guest_fxsave = vm_hw.fxsaveInit();

    return vcpu_obj;
}

/// Destroy a vCPU: kill its thread and free the struct.
pub fn destroy(vcpu_obj: *VCpu) void {
    const thread = vcpu_obj.thread;

    // Mark thread as exited so scheduler won't run it
    thread.state = .exited;

    // If on a CPU, IPI to force off
    if (sched.coreRunning(thread)) |core_id| {
        apic.sendSchedulerIpi(core_id);
    }

    // Remove from run queues
    sched.removeFromAnyRunQueue(thread);

    const gen = VCpuAllocator.currentGen(vcpu_obj);
    slab_instance.destroy(vcpu_obj, gen) catch unreachable;
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
    const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else apic.coreID();
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
            apic.sendSchedulerIpi(core_id);
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
        const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else apic.coreID();
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
            apic.sendSchedulerIpi(core_id);
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        }
        // If the vCPU entry loop (or a prior injection) already queued a
        // vector in pending_eventinj, don't clobber it. Route this vector
        // through the LAPIC IRR so the entry loop can pick it up next time.
        if (vcpu_obj.guest_state.pending_eventinj != 0) {
            vm_obj.injectExternal(interrupt.vector);
        } else {
            vm_hw.injectInterrupt(&vcpu_obj.guest_state, interrupt);
        }
        thread.state = .ready;
        const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else apic.coreID();
        sched.enqueueOnCore(target_core, thread);
    } else {
        // Not running — write pending interrupt into arch state
        if (vcpu_obj.guest_state.pending_eventinj != 0) {
            vm_obj.injectExternal(interrupt.vector);
        } else {
            vm_hw.injectInterrupt(&vcpu_obj.guest_state, interrupt);
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

    var last_tsc: u64 = cpu.rdtscLFenced();

    while (true) {
        if (vcpu_obj.loadState() != .running) {
            // Block until the VMM resumes us via vm_reply.
            thread.state = .blocked;
            cpu.enableInterrupts();
            sched.yield();
            last_tsc = cpu.rdtscLFenced();
            continue;
        }

        // Tick interrupt-controller timers with elapsed nanoseconds before
        // each VMRUN. TSC ticks at ~1 GHz on most hardware; treat 1 tick = 1 ns.
        const now_tsc = cpu.rdtscLFenced();
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
        const page_paddr = arch_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
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
        const page_paddr = arch_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return false;
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
    const pmm_mgr = &pmm.global_pmm.?;
    var page_addr = stack.base.addr;
    while (page_addr < stack.top.addr) {
        const kpage = try pmm_mgr.create(paging.PageMem(.page4k));
        const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
        try arch_paging.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), .{
            .write_perm = .write,
            .execute_perm = .no_execute,
            .cache_perm = .write_back,
            .global_perm = .global,
            .privilege_perm = .kernel,
        });
        page_addr += paging.PAGE4K;
    }
}
