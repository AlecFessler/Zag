const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const stack_mod = zag.memory.stack;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const FaultReason = zag.perms.permissions.FaultReason;
const kvm = zag.kvm;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const Process = zag.sched.process.Process;
const SlabAllocator = zag.memory.allocators.slab.SlabAllocator;
const Stack = zag.memory.stack.Stack;
const VAddr = zag.memory.address.VAddr;

pub const ThreadAllocator = SlabAllocator(Thread, false, 0, 64, true);

pub const Priority = enum(u3) {
    idle = 0,
    normal = 1,
    high = 2,
    realtime = 3,
    pinned = 4,
};

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
    tid: u64,
    ctx: *ArchCpuContext,
    kernel_stack: Stack,
    user_stack: ?Stack,
    process: *Process,
    next: ?*Thread = null,
    priority: Priority = .normal,
    pre_pin_priority: Priority = .normal,
    pre_pin_affinity: ?u64 = null,
    core_affinity: ?u64 = null,
    state: State = .ready,
    on_cpu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    pinned_exclusive: bool = false,
    futex_deadline_ns: u64 = 0,
    futex_paddr: PAddr = PAddr.fromInt(0),
    ipc_server: ?*Process = null,
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
    pmu_state: ?*arch.PmuState = null,

    pub fn deinit(self: *Thread) void {
        const proc = self.process;

        // §2.14.9: automatic pmu_stop on thread exit. The thread is no
        // longer running on any core by the time deinit runs (exit paths
        // leave the thread off its run queue before tearing it down), so
        // touching MSRs here would either be a no-op or clobber the PMU
        // state of whichever thread is currently running on the caller's
        // core. Just zero and free the state struct — real hardware
        // teardown happened at the latest pmuSave on context switch away.
        if (self.pmu_state) |state| {
            arch.pmuClearState(state);
            zag.sched.pmu.allocator.destroy(state);
            self.pmu_state = null;
        }

        // Remove thread handle from own perm table and handler's perm table
        proc.removeThreadHandle(self);
        if (proc.fault_handler_proc) |handler| {
            handler.removeThreadHandle(self);
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
                proc.lock.lock();
                const remaining = proc.threads[0..proc.num_threads];
                for (remaining) |t| {
                    if (kvm.vcpu.vcpuFromThread(vm_obj, t) == null) {
                        all_vcpu = false;
                        break;
                    }
                }
                proc.lock.unlock();

                if (all_vcpu) {
                    // Destroy the VM — marks all vCPU threads as exited and
                    // removes them from run queues.
                    vm_obj.destroy();

                    // Deinit the vCPU threads. Each deinit calls removeThread;
                    // the last one triggers lastThreadExited -> process exit.
                    // Snapshot the list since deinit mutates it.
                    proc.lock.lock();
                    var vcpu_threads: [Process.MAX_THREADS]*Thread = undefined;
                    var num_vcpu: u32 = 0;
                    for (proc.threads[0..proc.num_threads]) |t| {
                        vcpu_threads[num_vcpu] = t;
                        num_vcpu += 1;
                    }
                    proc.lock.unlock();

                    for (vcpu_threads[0..num_vcpu]) |t| {
                        t.deinit();
                    }
                }
            }
        }

        allocator.destroy(self);

        if (is_last) proc.lastThreadExited();
    }

    pub fn create(
        proc: *Process,
        entry: VAddr,
        arg: u64,
        num_stack_pages: u32,
    ) !*Thread {
        if (proc.num_threads >= Process.MAX_THREADS) return error.MaxThreads;

        const thread = try allocator.create(Thread);
        errdefer allocator.destroy(thread);

        thread.* = .{
            .tid = @atomicRmw(u64, &tid_counter, .Add, 1, .monotonic),
            .ctx = undefined,
            .kernel_stack = undefined,
            .user_stack = null,
            .process = proc,
        };

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
        thread.ctx = arch.prepareThreadContext(kstack_top, ustack_top, entry_fn, arg);

        proc.lock.lock();
        defer proc.lock.unlock();

        if (proc.num_threads >= Process.MAX_THREADS) return error.MaxThreads;
        thread.slot_index = @intCast(proc.num_threads);
        proc.threads[proc.num_threads] = thread;
        proc.num_threads += 1;

        return thread;
    }
};

fn mapKernelStack(stack: Stack) !void {
    const pmm_iface = pmm.global_pmm.?.allocator();
    var page_addr = stack.base.addr;
    var mapped: usize = 0;
    errdefer {
        var undo = stack.base.addr;
        var i: usize = 0;
        while (i < mapped) : (i += 1) {
            if (arch.unmapPage(memory_init.kernel_addr_space_root, VAddr.fromInt(undo))) |paddr| {
                const pg: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
                pmm_iface.destroy(pg);
            }
            undo += paging.PAGE4K;
        }
    }
    while (page_addr < stack.top.addr) : (page_addr += paging.PAGE4K) {
        const kpage = try pmm_iface.create(paging.PageMem(.page4k));
        @memset(std.mem.asBytes(kpage), 0);
        const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
        try arch.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), KERNEL_PERMS);
        mapped += 1;
    }
}

fn unmapKernelStack(stack: Stack) void {
    const pmm_iface = pmm.global_pmm.?.allocator();
    var page_addr = stack.base.addr;
    while (page_addr < stack.top.addr) : (page_addr += paging.PAGE4K) {
        if (arch.unmapPage(memory_init.kernel_addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
            const pg: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
            pmm_iface.destroy(pg);
        }
    }
}

pub var allocator: std.mem.Allocator = undefined;
pub var tid_counter: u64 = 1;
