const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const stack_mod = zag.memory.stack;

const ArchCpuContext = arch.cpu.ArchCpuContext;
const FaultReason = zag.perms.permissions.FaultReason;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = address.PAddr;
const Process = zag.proc.process.Process;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const Stack = stack_mod.Stack;
const VAddr = address.VAddr;

pub const ThreadAllocator = SecureSlab(Thread, 256);

pub const Priority = enum(u3) {
    idle = 0,
    normal = 1,
    high = 2,
    realtime = 3,
    pinned = 4,
};

pub const ThreadPriorityQueue = zag.utils.containers.priority_queue.PriorityQueue(
    Thread,
    "next",
    "priority",
    std.meta.fields(Priority).len,
);

pub const State = enum {
    running,
    ready,
    blocked,
    faulted,
    suspended,
    exited,
};

const KERNEL_PERMS = MemoryPerms{
    .write_perm = .write,
    .execute_perm = .no_execute,
    .cache_perm = .write_back,
    .global_perm = .global,
    .privilege_perm = .kernel,
};

pub const Thread = struct {
    _gen_lock: GenLock = .{},
    tid: u64,
    ctx: *ArchCpuContext,
    kernel_stack: Stack,
    user_stack: ?Stack,
    process: SlabRef(Process),
    next: ?SlabRef(Thread) = null,
    priority: Priority = .normal,
    pre_pin_priority: Priority = .normal,
    pre_pin_affinity: ?u64 = null,
    core_affinity: ?u64 = null,
    state: State = .ready,
    on_cpu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    pinned_exclusive: bool = false,
    futex_deadline_ns: u64 = 0,
    futex_paddr: PAddr = PAddr.fromInt(0),
    /// Index of the address that woke this thread from a multi-address futex wait.
    /// Set by wake() before waking; read by the thread after resuming.
    futex_wake_index: u8 = 0,
    /// Physical addresses this thread is waiting on in a multi-address futex wait.
    /// The thread is enqueued in all corresponding buckets simultaneously.
    futex_paddrs: [64]PAddr = [_]PAddr{PAddr.fromInt(0)} ** 64,
    /// Number of addresses in the current multi-address futex wait.
    futex_bucket_count: u8 = 0,
    ipc_server: ?SlabRef(Process) = null,
    slot_index: u8 = 0,
    /// Fault metadata, valid iff thread.state == .faulted (or the thread
    /// is queued in some fault box's wait queue / pending_thread slot).
    /// Filled in by the exception handler before the thread is enqueued
    /// on the fault box; consumed by sysFaultRecv when delivering the
    /// FaultMessage to userspace, and by sysFaultReply for FAULT_RESUME.
    fault_reason: FaultReason = .none,
    fault_addr: u64 = 0,
    fault_rip: u64 = 0,
    /// Pointer to the user iret frame (the `cpu.Context` captured at the
    /// original fault entry stub) living deeper on this thread's kernel
    /// stack. FAULT_RESUME_MODIFIED must write into this frame — NOT into
    /// `thread.ctx`, which after `faultBlock` -> `scheduler.yield()` points
    /// at a later kernel-mode context produced by the scheduler IPI.
    /// Set by `faultBlock`, cleared on FAULT_RESUME / FAULT_RESUME_MODIFIED.
    fault_user_ctx: ?*ArchCpuContext = null,
    /// Arch-specific PMU state (spec §2.14). `null` for threads that have
    /// never called `pmu_start`; allocated lazily on first start and freed
    /// on explicit `pmu_stop` or implicit release in `Thread.deinit`.
    pmu_state: ?*arch.pmu.PmuState = null,
    /// Lazy-FPU save buffer. The kernel never touches FP/SIMD itself
    /// (built with `-mno-sse`/`-mno-neon`), so userspace FPU state survives
    /// across syscalls untouched in registers. Eviction happens only when
    /// a different thread on the same core actually uses FP/SIMD —
    /// trapping #NM (x64) or ESR_EL1.EC=0x07 (aarch64) — at which point
    /// the trap handler `fxsave`/`stp q0..q31` into the previous owner's
    /// buffer and `fxrstor`/`ldp` from the new owner's. 576 bytes covers
    /// FXSAVE on x64 and V0-V31 + FPCR + FPSR on aarch64 (no SVE).
    /// Aligned 64 because XSAVE family requires it on x64 (forward-compat),
    /// and to hit a single cache line for the common case.
    fpu_state: [576]u8 align(64) = [_]u8{0} ** 576,
    /// Which core's `last_fpu_owner` slot currently points at this thread,
    /// or `null` if the thread has never used FPU since boot or has been
    /// evicted by another thread's trap. Set by the trap handler on save;
    /// read by the scheduler on cross-core migration to know whether the
    /// thread's regs need flushing from the source core's CPU before the
    /// destination core can safely `fxrstor`.
    last_fpu_core: ?u8 = null,

    /// Tear down and free this Thread slot. `carried_gen` is the
    /// generation carried by the caller's `SlabRef(Thread)` — we
    /// validate it when destroying the slab slot instead of
    /// reading `currentGen()` at destroy time, so a stale caller
    /// (whose ref predated a reallocation) panics cleanly rather
    /// than freeing the wrong tenant of the slot.
    pub fn deinit(self: *Thread, carried_gen: u63) void {
        // self-alive: deinit owns teardown of this thread's links; the
        // slot was reached via currentThread() / exited_thread slot /
        // sibling enumeration that already established liveness.
        const proc = self.process.ptr;

        // §2.14.9: automatic pmu_stop on thread exit. Serialize with
        // in-flight pmu syscalls on this thread via `proc._gen_lock`:
        // sysPmuStart/Read/Reset/Stop all touch `target_thread.pmu_state`
        // + the `*PmuState` fields under the same lock. Without this,
        // deinit destroying the PmuState slot would race a concurrent
        // `arch.pmu.pmuRead(state, ...)` and trigger a UAF / `destroy
        // unreachable`. Take, null, release, then do the hardware clear
        // + slab destroy outside the lock.
        const maybe_state = blk: {
            proc._gen_lock.lock();
            defer proc._gen_lock.unlock();
            const s = self.pmu_state;
            self.pmu_state = null;
            break :blk s;
        };
        if (maybe_state) |state| {
            arch.pmu.pmuClearState(state);
            const gen = state._gen_lock.currentGen();
            zag.syscall.pmu.slab_instance.destroy(state, gen) catch unreachable;
        }

        // Remove thread handle from own perm table and handler's perm table
        proc.removeThreadHandle(self);
        if (proc.fault_handler_proc) |handler_ref| {
            if (handler_ref.lock()) |handler| {
                // Verify freshness then drop gen-lock bit; removeThreadHandle
                // takes handler.perm_lock. The fault_handler relationship
                // invariant keeps handler alive across the brief window.
                handler_ref.unlock();
                handler.removeThreadHandle(self);
            } else |_| {}
        }

        stack_mod.destroyKernel(self.kernel_stack, memory_init.kernel_addr_space_root);

        const is_last = proc.removeThread(self);

        if (!is_last) {
            if (self.user_stack) |ustack| {
                stack_mod.destroyUser(ustack, &proc.vmm);
            }

            // §2.13.2: When a user thread exits and only vCPU threads remain,
            // destroy the VM (killing vCPU threads) and deinit them so the
            // process can proceed to exit. Without this, blocked vCPU threads
            // keep num_threads > 0 and lastThreadExited is never called.
            if (proc.vm) |vm_obj| {
                // Check if all remaining threads are vCPU threads.
                var all_vcpu = true;
                proc._gen_lock.lock();
                // self-alive: proc._gen_lock held — threads[] stable.
                for (proc.threads[0..proc.num_threads]) |t_ref| {
                    if (!arch.vm.threadIsVcpu(vm_obj, t_ref.ptr)) {
                        all_vcpu = false;
                        break;
                    }
                }
                proc._gen_lock.unlock();

                if (all_vcpu) {
                    // Destroy the VM — marks all vCPU threads as exited and
                    // removes them from run queues.
                    vm_obj.destroy();

                    // Deinit the vCPU threads. Each deinit calls removeThread;
                    // the last one triggers lastThreadExited -> process exit.
                    // Snapshot the list since deinit mutates it.
                    proc._gen_lock.lock();
                    var vcpu_threads: [Process.MAX_THREADS]SlabRef(Thread) = undefined;
                    var num_vcpu: u32 = 0;
                    for (proc.threads[0..proc.num_threads]) |t_ref| {
                        vcpu_threads[num_vcpu] = t_ref;
                        num_vcpu += 1;
                    }
                    proc._gen_lock.unlock();

                    // self-alive: we just snapshotted under proc._gen_lock,
                    // and deinit is what frees these slots — serial calls
                    // keep each slot live until its turn.
                    for (vcpu_threads[0..num_vcpu]) |t_ref| {
                        t_ref.ptr.deinit(@intCast(t_ref.gen));
                    }
                }
            }
        }

        slab_instance.destroy(self, carried_gen) catch unreachable;

        if (is_last) proc.lastThreadExited();
    }

    pub fn create(
        proc: *Process,
        entry: VAddr,
        arg: u64,
        num_stack_pages: u32,
    ) !*Thread {
        if (proc.num_threads >= Process.MAX_THREADS) return error.MaxThreads;

        const alloc_result = try slab_instance.create();
        const thread = alloc_result.ptr;
        errdefer slab_instance.destroy(thread, alloc_result.gen) catch unreachable;

        // Field-by-field assignment preserves `thread._gen_lock` (which
        // the slab allocator just set to the freshly-advanced live gen).
        // A whole-struct `thread.* = .{...}` would zero the gen-lock,
        // desyncing it from the allocator's gen and invalidating every
        // subsequent `lockWithGen` through a handle.
        thread.tid = @atomicRmw(u64, &tid_counter, .Add, 1, .monotonic);
        thread.ctx = undefined;
        thread.kernel_stack = undefined;
        thread.user_stack = null;
        thread.process = SlabRef(Process).init(proc, proc._gen_lock.currentGen());
        thread.next = null;
        thread.priority = .normal;
        thread.pre_pin_priority = .normal;
        thread.pre_pin_affinity = null;
        thread.core_affinity = null;
        thread.state = .ready;
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
        thread.last_fpu_core = null;
        arch.cpu.fpuStateInit(&thread.fpu_state);

        thread.kernel_stack = try stack_mod.createKernel();
        errdefer stack_mod.destroyKernel(thread.kernel_stack, memory_init.kernel_addr_space_root);

        try mapKernelStack(thread.kernel_stack);
        errdefer unmapKernelStack(thread.kernel_stack);

        const ustack = try stack_mod.createUser(&proc.vmm, num_stack_pages);
        thread.user_stack = ustack;
        errdefer stack_mod.destroyUser(ustack, &proc.vmm);

        const kstack_top = address.alignStack(thread.kernel_stack.top);
        const ustack_top = address.alignStack(ustack.top);
        const entry_fn: *const fn () void = @ptrFromInt(entry.addr);
        thread.ctx = arch.cpu.prepareThreadContext(kstack_top, ustack_top, entry_fn, arg);

        proc._gen_lock.lock();
        defer proc._gen_lock.unlock();

        if (proc.num_threads >= Process.MAX_THREADS) return error.MaxThreads;
        thread.slot_index = @intCast(proc.num_threads);
        proc.threads[proc.num_threads] = SlabRef(Thread).init(thread, thread._gen_lock.currentGen());
        proc.num_threads += 1;

        return thread;
    }
};

fn mapKernelStack(stack: Stack) !void {
    const pmm_mgr = &pmm.global_pmm.?;
    var page_addr = stack.base.addr;
    var mapped: usize = 0;
    errdefer {
        var undo = stack.base.addr;
        var i: usize = 0;
        while (i < mapped) {
            if (arch.paging.unmapPage(memory_init.kernel_addr_space_root, VAddr.fromInt(undo))) |paddr| {
                const pg: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
                pmm_mgr.destroy(pg);
            }
            undo += paging.PAGE4K;
            i += 1;
        }
    }
    while (page_addr < stack.top.addr) {
        const kpage = try pmm_mgr.create(paging.PageMem(.page4k));
        const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
        try arch.paging.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), KERNEL_PERMS);
        mapped += 1;
        page_addr += paging.PAGE4K;
    }
}

/// Allocate a kernel stack for a thread without a user stack (e.g. the
/// per-core idle thread on aarch64, which needs a real SP_EL1 to handle
/// interrupts taken while halting at EL1).
pub fn createKernelStack() !Stack {
    const stack = try stack_mod.createKernel();
    errdefer stack_mod.destroyKernel(stack, memory_init.kernel_addr_space_root);
    try mapKernelStack(stack);
    return stack;
}

fn unmapKernelStack(stack: Stack) void {
    const pmm_mgr = &pmm.global_pmm.?;
    var page_addr = stack.base.addr;
    while (page_addr < stack.top.addr) {
        if (arch.paging.unmapPage(memory_init.kernel_addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
            const pg: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
            pmm_mgr.destroy(pg);
        }
        page_addr += paging.PAGE4K;
    }
}

pub var slab_instance: ThreadAllocator = undefined;
pub var tid_counter: u64 = 1;
