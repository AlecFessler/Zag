const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PrivilegePerm = zag.perms.privilege.PrivilegePerm;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;

pub const USER_CODE_BASE: u64 = 0x400000;

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

    pub const MAX_THREADS = 16;

    pub fn createUserProcess(
        binary: []const u8,
    ) !*Process {
        if (binary.len > paging.PAGE4K) return error.BinaryTooLarge;

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

        const code_phys_page = try pmm_iface.create(paging.PageMem(.page4k));
        errdefer pmm_iface.destroy(code_phys_page);
        const code_bytes: [*]u8 = @ptrCast(code_phys_page);
        @memset(code_bytes[0..paging.PAGE4K], 0);
        @memcpy(code_bytes[0..binary.len], binary);

        const code_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(code_phys_page)), null);

        try arch.mapPage(
            proc.addr_space_root,
            code_phys,
            VAddr.fromInt(USER_CODE_BASE),
            .page4k,
            .{ .execute_perm = .execute, .privilege_perm = .user },
            pmm_iface,
        );

        const entry: *const fn () void = @ptrFromInt(USER_CODE_BASE);
        _ = try Thread.createThread(proc, entry, null);

        return proc;
    }
};

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
