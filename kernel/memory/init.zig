const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const address = zag.memory.address;
const boot = zag.boot;
const device_region_mod = zag.memory.device_region;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const shared = zag.memory.shared;
const vmm_mod = zag.memory.vmm;

const BuddyAllocator = zag.memory.buddy_allocator.BuddyAllocator;
const BumpAllocator = zag.memory.bump_allocator.BumpAllocator;
const HeapAllocator = zag.memory.heap_allocator.HeapAllocator;
const HeapTreeAllocator = zag.memory.heap_allocator.TreeAllocator;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const MMap = zag.boot.protocol.MMap;
const MMapEntry = zag.boot.protocol.MMapEntry;
const PAddr = zag.memory.address.PAddr;
const PhysicalMemoryManager = zag.memory.pmm.PhysicalMemoryManager;
const Range = zag.utils.range.Range;
const VAddr = zag.memory.address.VAddr;

const KA = address.KernelVA.KernelAllocators;

pub var kernel_addr_space_root: PAddr = undefined;

var bump_allocator: BumpAllocator = undefined;
var buddy_allocator: BuddyAllocator = undefined;

var vm_node_slab_bump: BumpAllocator = undefined;
var vm_tree_slab_bump: BumpAllocator = undefined;
var shm_slab_bump: BumpAllocator = undefined;
var device_region_slab_bump: BumpAllocator = undefined;

pub var proc_slab_backing: BumpAllocator = undefined;
pub var thread_slab_backing: BumpAllocator = undefined;

var heap_tree_bump: BumpAllocator = undefined;
var heap_tree_allocator: HeapTreeAllocator = undefined;
var heap_allocator_instance: HeapAllocator = undefined;

pub var heap_allocator: std.mem.Allocator = undefined;

pub fn init(firmware_mmap: MMap) !void {
    var mmap_entries: [boot.protocol.MAX_MMAP_ENTRIES]MMapEntry = undefined;
    const mmap = boot.protocol.collapseMMap(&firmware_mmap, &mmap_entries);

    var smallest_addr_region: MMapEntry = .{ .start_paddr = std.math.maxInt(u64), .num_pages = 0, .type = .free };
    var largest_addr_free_region: MMapEntry = .{ .start_paddr = 0, .num_pages = 0, .type = .free };
    var largest_free_region: MMapEntry = .{ .start_paddr = 0, .num_pages = 0, .type = .free };
    for (mmap) |entry| {
        if (entry.start_paddr < smallest_addr_region.start_paddr) {
            smallest_addr_region = entry;
        }
        if (entry.type == .free and entry.start_paddr > largest_addr_free_region.start_paddr) {
            largest_addr_free_region = entry;
        }
        if (entry.type == .free and entry.num_pages > largest_free_region.num_pages) {
            largest_free_region = entry;
        }
    }

    const bump_alloc_start_phys = PAddr.fromInt(largest_free_region.start_paddr);
    const bump_alloc_end_phys = PAddr.fromInt(largest_free_region.start_paddr + largest_free_region.num_pages * paging.PAGE4K);
    bump_allocator = BumpAllocator.init(bump_alloc_start_phys.addr, bump_alloc_end_phys.addr);
    const bump_alloc_iface: std.mem.Allocator = bump_allocator.allocator();

    const addr_space_root_phys = arch.getAddrSpaceRoot();
    kernel_addr_space_root = addr_space_root_phys;
    const addr_space_root_id_virt = VAddr.fromPAddr(addr_space_root_phys, 0);

    var physmap_page_count: u64 = 0;
    for (mmap) |entry| {
        if (entry.type != .free and entry.type != .acpi) continue;

        const end_phys = PAddr.fromInt(entry.start_paddr + entry.num_pages * paging.PAGE4K);
        var current_phys = PAddr.fromInt(entry.start_paddr);
        while (current_phys.addr < end_phys.addr) {
            const physmap_virt = VAddr.fromPAddr(current_phys, null);
            const remaining = end_phys.addr - current_phys.addr;
            const chosen_size = blk: {
                if (std.mem.isAligned(current_phys.addr, paging.PAGE1G) and remaining >= paging.PAGE1G)
                    break :blk paging.PageSize.page1g;
                if (std.mem.isAligned(current_phys.addr, paging.PAGE2M) and remaining >= paging.PAGE2M)
                    break :blk paging.PageSize.page2m;
                break :blk paging.PageSize.page4k;
            };

            const physmap_perms: MemoryPerms = .{
                .write_perm = .write,
                .execute_perm = .no_execute,
                .cache_perm = .write_back,
                .global_perm = .global,
                .privilege_perm = .kernel,
            };

            try arch.mapPageBoot(
                addr_space_root_id_virt,
                current_phys,
                physmap_virt,
                chosen_size,
                physmap_perms,
                bump_alloc_iface,
            );

            current_phys.addr += @intFromEnum(chosen_size);
            physmap_page_count += 1;
        }
    }

    const bump_alloc_start_virt = VAddr.fromPAddr(bump_alloc_start_phys, null);
    const bump_alloc_free_phys = PAddr.fromInt(bump_allocator.free_addr);
    const bump_alloc_free_virt = VAddr.fromPAddr(bump_alloc_free_phys, null);
    const bump_alloc_end_virt = VAddr.fromPAddr(bump_alloc_end_phys, null);
    bump_allocator.start_addr = bump_alloc_start_virt.addr;
    bump_allocator.free_addr = bump_alloc_free_virt.addr;
    bump_allocator.end_addr = bump_alloc_end_virt.addr;

    arch.dropIdentityMapping();
    const buddy_alloc_start_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignForward(u64, smallest_addr_region.start_paddr, paging.PAGE4K)),
        null,
    );
    const buddy_alloc_end_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignBackward(
            u64,
            largest_addr_free_region.start_paddr + largest_addr_free_region.num_pages * paging.PAGE4K,
            paging.PAGE4K,
        )),
        null,
    );
    buddy_allocator = try BuddyAllocator.init(
        buddy_alloc_start_virt.addr,
        buddy_alloc_end_virt.addr,
        bump_alloc_iface,
    );
    const buddy_alloc_iface = buddy_allocator.allocator();

    for (mmap) |entry| {
        if (entry.type != .free) continue;

        const entry_start_virt = VAddr.fromPAddr(PAddr.fromInt(entry.start_paddr), null);
        const entry_end_virt = VAddr.fromPAddr(
            PAddr.fromInt(entry.start_paddr + entry.num_pages * paging.PAGE4K),
            null,
        );
        const entry_range: Range = .{
            .start = entry_start_virt.addr,
            .end = entry_end_virt.addr,
        };

        const bump_alloc_range: Range = .{
            .start = bump_allocator.start_addr,
            .end = bump_allocator.free_addr,
        };
        const low_memory_range: Range = .{
            .start = VAddr.fromPAddr(PAddr.fromInt(0), null).addr,
            .end = VAddr.fromPAddr(PAddr.fromInt(0x100000), null).addr,
        };

        var useable_range: Range = entry_range;
        if (entry_range.overlapsWith(bump_alloc_range)) {
            useable_range = entry_range.removeOverlap(bump_alloc_range);
        } else if (entry_range.overlapsWith(low_memory_range)) {
            if (entry_range.start >= low_memory_range.start and entry_range.end <= low_memory_range.end) {
                continue;
            }
            useable_range = entry_range.removeOverlap(low_memory_range);
        }

        buddy_allocator.addRegion(useable_range.start, useable_range.end);
    }

    pmm.global_pmm = PhysicalMemoryManager.init(buddy_alloc_iface);

    vm_node_slab_bump = BumpAllocator.init(KA.vm_node_slab.start, KA.vm_node_slab.end);
    vm_tree_slab_bump = BumpAllocator.init(KA.vm_tree_slab.start, KA.vm_tree_slab.end);
    shm_slab_bump = BumpAllocator.init(KA.shm_slab.start, KA.shm_slab.end);
    device_region_slab_bump = BumpAllocator.init(KA.device_region_slab.start, KA.device_region_slab.end);
    proc_slab_backing = BumpAllocator.init(KA.proc_slab.start, KA.proc_slab.end);
    thread_slab_backing = BumpAllocator.init(KA.thread_slab.start, KA.thread_slab.end);

    try vmm_mod.initSlabs(vm_node_slab_bump.allocator(), vm_tree_slab_bump.allocator());
    try device_region_mod.initSlab(device_region_slab_bump.allocator());

    shared.slab_allocator_instance = try shared.SharedMemoryAllocator.init(shm_slab_bump.allocator());
    shared.allocator = shared.slab_allocator_instance.allocator();
}

pub fn initHeap() !void {
    heap_tree_bump = BumpAllocator.init(KA.heap_tree.start, KA.heap_tree.end);
    heap_tree_allocator = try HeapTreeAllocator.init(heap_tree_bump.allocator());

    heap_allocator_instance = HeapAllocator.init(
        KA.heap.start,
        KA.heap.end,
        &heap_tree_allocator,
    );
    heap_allocator = heap_allocator_instance.allocator();

    shared.pages_allocator = heap_allocator;
}
