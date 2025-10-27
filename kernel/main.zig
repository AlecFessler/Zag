const std = @import("std");
const zag = @import("zag");
const boot_defs = @import("boot_defs");

const cpu = zag.x86.Cpu;
const gdt = zag.x86.Gdt;
const idt = zag.x86.Idt;
const isr = zag.x86.Isr;
const serial = zag.x86.Serial;
const paging = zag.x86.Paging;
const pmm_mod = zag.memory.PhysicalMemoryManager;
const vmm_mod = zag.memory.VirtualMemoryManager;

const BuddyAllocator = zag.memory.BuddyAllocator.BuddyAllocator;
const BumpAllocator = zag.memory.BumpAllocator.BumpAllocator;
const HeapAllocator = zag.memory.HeapAllocator.HeapAllocator;
const HeapTreeAllocator = zag.memory.HeapAllocator.TreeAllocator;
const PAddr = paging.PAddr;
const VAddr = paging.VAddr;
const PhysicalMemoryManager = pmm_mod.PhysicalMemoryManager;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;

const PAGE4K = @intFromEnum(paging.PageSize.Page4K);
const PAGE1G = @intFromEnum(paging.PageSize.Page1G);

extern const __stackguard_lower: [*]const u8;

/// Triggers a kernel panic and halts execution.
///
/// Arguments:
/// - `msg`: description of the failure
/// - `error_return_trace`: optional Zig stack trace
/// - `ret_addr`: optional return address for context
pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    zag.panic.panic(msg, error_return_trace, ret_addr);
}

export fn kEntry(boot_info: boot_defs.BootInfo) callconv(.{ .x86_64_sysv = .{} }) noreturn {
    asm volatile (
        \\movq %[new_stack], %%rsp
        :
        : [new_stack] "r" (@intFromPtr(&__stackguard_lower) - 0x10),
    );
    kMain(boot_info) catch {
        @panic("Exiting...");
    };
    unreachable;
}

fn kMain(boot_info: boot_defs.BootInfo) !void {
    serial.init(.com1, 115200);
    gdt.init(VAddr.fromInt(@intFromPtr(&__stackguard_lower)));
    idt.init();
    isr.init();

    var mmap_entries_array: [boot_defs.MAX_MMAP_ENTRIES]boot_defs.MMapEntry = undefined;
    const mmap = boot_defs.collapseMmap(
        &boot_info.mmap,
        &mmap_entries_array,
    );

    // find largest contiguous free region for pmm
    var largest_free_region = boot_defs.MMapEntry{
        .start_paddr = 0,
        .num_pages = 0,
        .type = .free,
    };
    for (mmap) |entry| {
        if (entry.type == .free and entry.num_pages > largest_free_region.num_pages) {
            largest_free_region = entry;
        }
    }

    // early boot identity mapped bump allocator
    const bump_alloc_start_phys = PAddr.fromInt(largest_free_region.start_paddr);
    const bump_alloc_end_phys = PAddr.fromInt(largest_free_region.start_paddr + largest_free_region.num_pages * PAGE4K);
    var bump_allocator = BumpAllocator.init(
        bump_alloc_start_phys.addr,
        bump_alloc_end_phys.addr,
    );
    const bump_alloc_iface = bump_allocator.allocator();

    const ksyms_bytes: []const u8 = boot_info.ksyms.ptr[0..boot_info.ksyms.len];
    try zag.panic.initSymbolsFromSlice(ksyms_bytes, bump_alloc_iface);

    const pml4_paddr = paging.read_cr3();
    const pml4_vaddr = VAddr.fromPAddr(pml4_paddr, .identity);
    paging.physMapRegion(
        pml4_vaddr,
        bump_alloc_start_phys,
        bump_alloc_end_phys,
        bump_alloc_iface,
    );

    const buddy_alloc_required_bytes = BuddyAllocator.requiredMemory(
        bump_allocator.free_addr,
        bump_allocator.end_addr,
    );
    const buddy_alloc_start_phys = PAddr.fromInt(std.mem.alignForward(
        u64,
        bump_allocator.free_addr + buddy_alloc_required_bytes,
        PAGE4K,
    ));
    const buddy_alloc_end_phys = PAddr.fromInt(std.mem.alignBackward(
        u64,
        bump_allocator.end_addr,
        PAGE4K,
    ));
    std.debug.assert(buddy_alloc_start_phys.addr < buddy_alloc_end_phys.addr);
    const buddy_alloc_start_virt = VAddr.fromPAddr(buddy_alloc_start_phys, .physmap);
    const buddy_alloc_end_virt = VAddr.fromPAddr(buddy_alloc_end_phys, .physmap);

    var buddy_allocator: BuddyAllocator = BuddyAllocator.init(
        buddy_alloc_start_virt.addr,
        buddy_alloc_end_virt.addr,
        bump_alloc_iface,
    ) catch @panic("Failed to allocate memory for buddy allocator!");
    const buddy_alloc_iface = buddy_allocator.allocator();

    pmm_mod.global_pmm = PhysicalMemoryManager.init(buddy_alloc_iface);

    // should drop identity mappings at this point

    const pml4_slot_size = PAGE1G * paging.PAGE_TABLE_SIZE;
    const vmm_start_vaddr = paging.pml4SlotBase(@intFromEnum(paging.AddressSpace.kvmm));
    const vmm_end_vaddr = VAddr.fromInt(vmm_start_vaddr.addr + pml4_slot_size);

    vmm_mod.global_vmm = VirtualMemoryManager.init(
        vmm_start_vaddr,
        vmm_end_vaddr,
    );
    var vmm = &vmm_mod.global_vmm.?;

    const heap_vaddr_space_start = vmm.reserve(
        PAGE1G * 256,
        std.mem.Alignment.fromByteUnits(PAGE4K),
    ) catch @panic("VMM doesn't have enough address space for heap allocator!");
    const heap_vaddr_space_end = VAddr.fromInt(heap_vaddr_space_start.addr + PAGE1G * 256);
    serial.print("heap vaddr start {X} end {X}\n", .{
        heap_vaddr_space_start.addr,
        heap_vaddr_space_end.addr,
    });

    const heap_tree_vaddr_space_start = vmm.reserve(
        PAGE1G,
        std.mem.Alignment.fromByteUnits(PAGE4K),
    ) catch @panic("VMM doesn't have enough address space for heap tree allocator!");
    const heap_tree_vaddr_space_end = VAddr.fromInt(heap_tree_vaddr_space_start.addr + PAGE1G);
    serial.print("heap vaddr start {X} end {X}\n", .{
        heap_tree_vaddr_space_start.addr,
        heap_tree_vaddr_space_end.addr,
    });

    var heap_tree_backing_allocator = BumpAllocator.init(
        heap_tree_vaddr_space_start.addr,
        heap_tree_vaddr_space_end.addr,
    );
    const heap_tree_backing_allocator_iface = heap_tree_backing_allocator.allocator();
    var heap_tree_allocator = HeapTreeAllocator.init(
        heap_tree_backing_allocator_iface,
    ) catch @panic("Failed to initialize heap allocator's tree allocator!");

    var heap_allocator = HeapAllocator.init(
        heap_vaddr_space_start.addr,
        heap_vaddr_space_end.addr,
        &heap_tree_allocator,
    );
    const heap_allocator_iface = heap_allocator.allocator();

    const slice = heap_allocator_iface.alloc(u8, 10) catch unreachable;
    serial.print("Slice addr {X}", .{@intFromPtr(slice.ptr)});

    cpu.halt();
}
