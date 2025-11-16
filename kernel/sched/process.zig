const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PrivilegeLevel = zag.perms.privilege.PrivilegeLevel;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm;

pub const ProcessAllocator = SlabAllocator(
    Process,
    false,
    0,
    64,
);

pub const Process = struct {
    pid: u64,
    cpl: PrivilegeLevel,
    pml4_virt: VAddr,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]*Thread,
    num_threads: u64,

    const MAX_THREADS = 16;

    pub fn createUserProcess(
        entry: *const fn () void,
    ) !*Process {
        const proc = try process_allocator.create(Process);
        errdefer process_allocator.destroy(proc);

        proc.pid = pid_counter;
        pid_counter += 1;

        // NOTE: This all needs to be made arch agnostic
        proc.cpl = .ring_3;

        const pmm_iface = pmm.global_pmm.?.allocator();
        const pml4_page = try pmm_iface.create(paging.PageMem(.Page4K));
        errdefer pmm_iface.destroy(pml4_page);

        const pml4_bytes: [*]u8 = @ptrCast(pml4_page);
        @memset(pml4_bytes[0..paging.PAGE4K], 0);

        proc.pml4_virt = VAddr.fromInt(@intFromPtr(pml4_page));
        // NOTE: Will need something like arch.copyKernelMappings(root)
        paging.copyKernelPml4Mappings(@ptrFromInt(proc.pml4_virt.addr));

        // NOTE: This is the wrong range
        const vmm_start = VAddr.fromInt(paging.PAGE4K);
        const vmm_end = VAddr.fromInt(paging.pml4SlotBase(
            @intFromEnum(paging.Pml4SlotIndices.uvmm_end),
        ).addr + paging.PAGE1G * paging.PAGE_TABLE_SIZE);

        proc.vmm = VirtualMemoryManager.init(
            vmm_start,
            vmm_end,
        );

        proc.num_threads = 0;
        _ = try Thread.createThread(proc, entry);

        return proc;
    }
};

pub var allocator: std.mem.Allocator = undefined;
var pid_counter: u64 = 1;
