const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PrivilegePerm = zag.perms.privilege.PrivilegePerm;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;

pub const ProcessAllocator = SlabAllocator(
    Process,
    false,
    0,
    64,
);

pub const Process = struct {
    pid: u64,
    privilege: PrivilegePerm,
    addr_space_root: VAddr,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]*Thread,
    num_threads: u64,

    pub fn createUserProcess(
        entry: *const fn () void,
    ) !*Process {
        const proc = try allocator.create(Process);
        errdefer allocator.destroy(proc);

        proc.pid = pid_counter;
        pid_counter += 1;

        proc.privilege = .user;

        const pmm_iface = pmm.global_pmm.?.allocator();
        const new_addr_space_root_page = try pmm_iface.create(paging.PageMem(.page4k));
        errdefer pmm_iface.destroy(new_addr_space_root_page);

        const new_addr_space_root_bytes: [*]u8 = @ptrCast(new_addr_space_root_page);
        @memset(new_addr_space_root_bytes[0..paging.PAGE4K], 0);

        proc.addr_space_root = VAddr.fromInt(@intFromPtr(new_addr_space_root_page));
        arch.copyKernelMappings(proc.addr_space_root);

        proc.vmm = VirtualMemoryManager.init(
            VAddr.fromInt(address.AddrSpacePartition.user.start),
            VAddr.fromInt(address.AddrSpacePartition.user.end),
        );

        proc.num_threads = 0;
        _ = try Thread.createThread(proc, entry);

        return proc;
    }
};

const MAX_THREADS = 16;

pub var allocator: std.mem.Allocator = undefined;

pub var global_kproc: Process = .{
    .pid = 0,
    .privilege = .kernel,
    .addr_space_root = undefined,
    .vmm = undefined,
    .threads = undefined,
    .num_threads = 0,
};

var pid_counter: u64 = 1;
