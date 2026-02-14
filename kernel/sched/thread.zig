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

pub const Thread = struct {
    tid: u64,
    ctx: *ArchCpuContext,
    ustack_base: ?VAddr,
    kstack_base: VAddr,
    proc: *Process,
    next: ?*Thread = null,
    core_affinity: ?u64 = null,

    pub fn createThread(
        proc: *Process,
        entry: *const fn () void,
        affinity: ?u64,
    ) !*Thread {
        if (proc.num_threads + 1 >= Process.MAX_THREADS) return error.MaxThreads;

        const thread: *Thread = try allocator.create(Thread);
        errdefer allocator.destroy(thread);

        thread.tid = tid_counter;
        tid_counter += 1;
        thread.core_affinity = affinity;

        const pmm_iface = pmm.global_pmm.?.allocator();

        const kstack_page = try pmm_iface.create(paging.PageMem(.page4k));
        errdefer pmm_iface.destroy(kstack_page);
        const kstack_virt = VAddr.fromInt(@intFromPtr(kstack_page));
        const kstack_base = kstack_virt.addr + paging.PAGE4K;
        thread.kstack_base = address.alignStack(VAddr.fromInt(kstack_base));

        if (proc.privilege == .user) {
            const ustack_virt = try proc.vmm.reserve(paging.PAGE4K, paging.pageAlign(.page4k));

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

            const ustack_base = ustack_virt.addr + paging.PAGE4K;
            thread.ustack_base = address.alignStack(VAddr.fromInt(ustack_base));
        } else {
            thread.ustack_base = null;
        }

        thread.ctx = arch.prepareInterruptFrame(thread.kstack_base, thread.ustack_base, entry);
        thread.proc = proc;
        proc.threads[proc.num_threads] = thread;
        proc.num_threads += 1;

        return thread;
    }
};

pub var allocator: std.mem.Allocator = undefined;
var tid_counter: u64 = 0;
