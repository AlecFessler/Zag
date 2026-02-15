const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const Process = zag.sched.process.Process;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const VAddr = zag.memory.address.VAddr;

pub const ThreadAllocator = SlabAllocator(
    Thread,
    false,
    0,
    64,
);

pub const KSTACK_PAGES = 4;

pub const State = enum {
    running,
    ready,
    blocked,
    exited,
};

pub const Thread = struct {
    tid: u64,
    ctx: *ArchCpuContext,
    ustack_top: ?VAddr,
    ustack_bottom: ?VAddr,
    kstack_top: VAddr,
    kstack_bottom: VAddr,
    proc: *Process,
    next: ?*Thread = null,
    core_affinity: ?u64 = null,
    state: State = .ready,
    last_in_proc: bool = false,
    // prevents a race in WaitQueue.wait() where the thread marks itself as blocked
    // then another core calls WaitQueue.wakeOne and sets its to ready and enqueues
    // it to the run queue but the thread is still executing on the original core because
    // it hasn't called yield yet.
    on_cpu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn deinit(self: *Thread) void {
        const pmm_iface = pmm.global_pmm.?.allocator();
        const last = self.last_in_proc;
        const proc = self.proc;

        const kstack_ptr: [*]align(paging.PAGE4K) u8 = @ptrFromInt(self.kstack_bottom.addr);
        pmm_iface.free(kstack_ptr[0 .. KSTACK_PAGES * paging.PAGE4K]);

        if (!last) {
            if (self.ustack_bottom) |ustack_bottom| {
                if (arch.unmapPage(proc.addr_space_root, ustack_bottom, .page4k)) |phys| {
                    const phys_virt: [*]align(paging.PAGE4K) u8 = @ptrFromInt(VAddr.fromPAddr(phys, null).addr);
                    pmm_iface.free(phys_virt[0..paging.PAGE4K]);
                }
                proc.vmm.removeReservation(ustack_bottom);
            }
        }

        allocator.destroy(self);

        if (last) {
            proc.deinit();
        }
    }

    pub fn createThread(
        proc: *Process,
        entry: *const fn () void,
        affinity: ?u64,
    ) !*Thread {
        if (proc.num_threads + 1 >= Process.MAX_THREADS) return error.MaxThreads;

        const thread: *Thread = try allocator.create(Thread);
        errdefer allocator.destroy(thread);

        thread.tid = @atomicRmw(u64, &tid_counter, .Add, 1, .monotonic);
        thread.core_affinity = affinity;
        thread.last_in_proc = false;

        const pmm_iface = pmm.global_pmm.?.allocator();

        const kstack = try pmm_iface.alignedAlloc(u8, paging.pageAlign(.page4k), paging.PAGE4K * KSTACK_PAGES);
        thread.kstack_bottom = VAddr.fromInt(@intFromPtr(kstack.ptr));
        thread.kstack_top = address.alignStack(VAddr.fromInt(thread.kstack_bottom.addr + (paging.PAGE4K * KSTACK_PAGES)));

        if (proc.privilege == .user) {
            const ustack_virt = try proc.vmm.reserve(
                paging.PAGE4K,
                paging.pageAlign(.page4k),
                .{ .read = true, .write = true },
            );
            const ustack_phys_page = try pmm_iface.create(paging.PageMem(.page4k));
            errdefer pmm_iface.destroy(ustack_phys_page);
            const ustack_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(ustack_phys_page)), null);
            try arch.mapPage(
                proc.addr_space_root,
                ustack_phys,
                ustack_virt,
                .page4k,
                .{ .write_perm = .write, .privilege_perm = .user },
                pmm_iface,
            );
            thread.ustack_bottom = ustack_virt;
            thread.ustack_top = address.alignStack(VAddr.fromInt(ustack_virt.addr + paging.PAGE4K));
        } else {
            thread.ustack_top = null;
            thread.ustack_bottom = null;
        }

        thread.ctx = arch.prepareInterruptFrame(thread.kstack_top, thread.ustack_top, entry);
        thread.proc = proc;

        proc.lock.lock();
        defer proc.lock.unlock();

        if (proc.num_threads >= Process.MAX_THREADS) return error.MaxThreads;
        proc.threads[proc.num_threads] = thread;
        proc.num_threads += 1;
        thread.state = .ready;
        return thread;
    }
};

pub var allocator: std.mem.Allocator = undefined;
var tid_counter: u64 = 0;
