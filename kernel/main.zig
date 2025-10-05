const std = @import("std");

const memory = @import("memory");
const bump_alloc = memory.BumpAllocator;
const buddy_alloc = memory.BuddyAllocator;
const heap_alloc = memory.HeapAllocator;
const pmm_mod = memory.PhysicalMemoryManager;
const vmm_mod = memory.VirtualMemoryManager;
const x86 = @import("x86");
const cpu = x86.Cpu;
const paging = x86.Paging;
const vga = x86.Vga;
const gdt = x86.Gdt;
const idt = x86.Idt;
const isr = x86.Isr;
const interrupts = x86.Interrupts;
const multiboot = x86.Multiboot;

const BumpAllocator = bump_alloc.BumpAllocator;
const BuddyAllocator = buddy_alloc.BuddyAllocator;
const HeapAllocator = heap_alloc.HeapAllocator;
const HeapTreeAllocator = heap_alloc.TreeAllocator;
const PhysicalMemoryManager = pmm_mod.PhysicalMemoryManager;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;

extern const _kernel_end: u8;

export fn kmain(
    stack_top_vaddr: u64,
    magic: u32,
    mbi_paddr: u32,
) callconv(.c) void {
    vga.initialize(.White, .Black);

    if (magic != multiboot.MAGIC) {
        @panic("Not a multiboot compliant boot");
    }

    const mbi_vaddr: u64 = paging.physToVirt(mbi_paddr);
    const mbi: *const multiboot.MultibootInfo = @ptrFromInt(mbi_vaddr);

    if (!multiboot.checkFlag(mbi.flags, 6)) {
        @panic("Mmap_* are invalid!");
    }

    var memory_regions_buffer: [multiboot.MAX_REGIONS]multiboot.MemoryRegion = undefined;
    const memory_regions: []multiboot.MemoryRegion = multiboot.parseMemoryMap(
        mbi,
        &memory_regions_buffer,
    );

    var max_end_paddr: u64 = 0;
    for (memory_regions) |region| {
        if (region.region_type != multiboot.MemoryRegionType.Available) continue;
        const end_paddr = region.addr + region.len;
        if (end_paddr > max_end_paddr) max_end_paddr = end_paddr;
    }
    const region_end_vaddr = paging.physToVirt(max_end_paddr);

    const kernel_end: u64 = @intCast(@intFromPtr(&_kernel_end));
    const kernel_end_paddr = paging.virtToPhys(kernel_end);
    const page4K = @intFromEnum(paging.PageSize.Page4K);
    const page4k_align = std.mem.Alignment.fromByteUnits(page4K);

    const useable_region_start_paddr = std.mem.alignForward(
        u64,
        kernel_end_paddr,
        page4K,
    );
    const useable_region_start_vaddr = paging.physToVirt(useable_region_start_paddr);

    var bump_allocator = BumpAllocator.init(
        useable_region_start_vaddr,
        region_end_vaddr,
    );
    const bump_alloc_iface = bump_allocator.allocator();

    for (memory_regions) |region| {
        if (region.region_type != multiboot.MemoryRegionType.Available) continue;

        const start_paddr = std.mem.alignForward(
            u64,
            region.addr,
            page4K,
        );
        const end_paddr = std.mem.alignBackward(
            u64,
            region.addr + region.len,
            page4K,
        );
        if (end_paddr <= start_paddr) continue;

        paging.physMapRegion(
            start_paddr,
            end_paddr,
            bump_alloc_iface,
        );
    }

    const double_fault_stack_top = bump_alloc_iface.alloc(
        paging.PageMem(paging.PageSize.Page4K),
        1,
    ) catch @panic("Kernel OOM!");
    const double_fault_stack_top_vaddr = @intFromPtr(double_fault_stack_top.ptr);

    gdt.init(
        stack_top_vaddr,
        double_fault_stack_top_vaddr,
    );
    idt.init();
    isr.init();

    const buddy_metadata_bytes = BuddyAllocator.requiredMemory(
        bump_allocator.free_addr,
        bump_allocator.end_addr,
    );
    const buddy_start_vaddr = std.mem.alignForward(
        u64,
        bump_allocator.free_addr + buddy_metadata_bytes,
        page4K,
    );
    const buddy_end_vaddr = std.mem.alignBackward(
        u64,
        bump_allocator.end_addr,
        page4K,
    );
    std.debug.assert(buddy_end_vaddr > buddy_start_vaddr);

    var buddy_allocator: BuddyAllocator = BuddyAllocator.init(
        buddy_start_vaddr,
        buddy_end_vaddr,
        bump_alloc_iface,
    ) catch @panic("Failed to allocate memory for buddy allocator!");
    std.debug.assert(bump_allocator.free_addr <= buddy_start_vaddr);
    const buddy_alloc_iface = buddy_allocator.allocator();

    pmm_mod.global_pmm = PhysicalMemoryManager.init(buddy_alloc_iface);

    const page1G = @intFromEnum(paging.PageSize.Page1G);
    const pml4_slot_size = page1G * paging.PAGE_TABLE_SIZE;
    const vmm_start_vaddr = paging.pml4SlotBase(@intFromEnum(paging.AddressSpace.kvmm));
    const vmm_end_vaddr = vmm_start_vaddr + pml4_slot_size;

    vmm_mod.global_vmm = VirtualMemoryManager.init(
        vmm_start_vaddr,
        vmm_end_vaddr,
    );
    var vmm = &vmm_mod.global_vmm.?;

    const heap_addr_space_size = pml4_slot_size / 2;
    const heap_tree_addr_space_size = page1G;

    const heap_addr_space_start = vmm.reserve(
        heap_addr_space_size,
        page4k_align,
    ) catch @panic("VMM doesn't have enough address space for heap allocator!");
    const heap_addr_space_end = heap_addr_space_start + heap_addr_space_size;

    const heap_tree_addr_space_start = vmm.reserve(
        heap_tree_addr_space_size,
        page4k_align,
    ) catch @panic("VMM doesn't have enough address space for heap tree allocator!");
    const heap_tree_addr_space_end = heap_tree_addr_space_start + heap_tree_addr_space_size;

    vga.print("Heap addr space start {X} end {X} size {}\n", .{
        heap_addr_space_start,
        heap_addr_space_end,
        heap_addr_space_size,
    });
    vga.print("Heap tree addr space start {X} end {X} size {}\n", .{
        heap_tree_addr_space_start,
        heap_tree_addr_space_end,
        heap_tree_addr_space_size,
    });

    var heap_tree_allocator_backing = BumpAllocator.init(
        heap_tree_addr_space_start,
        heap_tree_addr_space_end,
    );
    const heap_tree_allocator_backing_iface = heap_tree_allocator_backing.allocator();

    var heap_tree_allocator = HeapTreeAllocator.init(
        heap_tree_allocator_backing_iface,
    ) catch @panic("Heap tree's backing allocator is OOM!");

    var heap_allocator = HeapAllocator.init(
        @intCast(heap_addr_space_start),
        @intCast(heap_addr_space_end),
        &heap_tree_allocator,
    );
    const heap_alloc_iface = heap_allocator.allocator();

    const heap_buffer = heap_alloc_iface.alloc(u8, 10) catch @panic("Heap allocator OOM!");
    vga.print("Heap buffer ptr {X}", .{@intFromPtr(heap_buffer.ptr)});

    cpu.halt();
}

pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    _ = error_return_trace;
    vga.setColor(.White, .Blue);
    if (ret_addr) |ra| {
        vga.print("KERNEL PANIC: {s}, ret_addr {X}\n", .{ msg, ra });
    } else {
        vga.print("KERNEL PANIC: {s}\n", .{msg});
    }
    cpu.halt();
}
