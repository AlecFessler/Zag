const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const stack_mod = zag.memory.stack;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const Process = zag.sched.process.Process;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const Stack = zag.memory.stack.Stack;
const VAddr = zag.memory.address.VAddr;

pub const ThreadAllocator = SlabAllocator(Thread, false, 0, 64);

pub const State = enum {
    running,
    ready,
    blocked,
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
    core_affinity: ?u64 = null,
    state: State = .ready,
    last_in_proc: bool = false,
    on_cpu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn deinit(self: *Thread) void {
        const last = self.last_in_proc;
        const proc = self.process;

        stack_mod.destroyKernel(self.kernel_stack, memory_init.kernel_addr_space_root);

        if (!last) {
            if (self.user_stack) |ustack| {
                stack_mod.destroyUser(ustack, &proc.vmm);
            }
        }

        allocator.destroy(self);

        if (last) proc.exit();
    }

    pub fn create(
        proc: *Process,
        entry: VAddr,
        arg: u64,
        num_stack_pages: u32,
    ) !*Thread {
        if (proc.num_threads + 1 >= Process.MAX_THREADS) return error.MaxThreads;

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
var tid_counter: u64 = 0;
