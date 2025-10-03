const std = @import("std");

const memory = @import("memory");
const bump_alloc = memory.BumpAllocator;
const buddy_alloc = memory.BuddyAllocator;
const heap_alloc = memory.HeapAllocator;
const pmm_mod = memory.PhysicalMemoryManager;
const vmm_mod = memory.VirtualMemoryManager;
const x86 = @import("x86");
const paging = x86.Paging;
const vga = x86.Vga;
const gdt = x86.Gdt;
const idt = x86.Idt;
const isr = x86.Isr;
const interrupts = x86.Interrupts;
const multiboot = @import("boot/grub/multiboot.zig");

const BumpAllocator = bump_alloc.BumpAllocator;
const BuddyAllocator = buddy_alloc.BuddyAllocator;
const HeapAllocator = heap_alloc.HeapAllocator;
const HeapTreeAllocator = heap_alloc.TreeAllocator;
const PhysicalMemoryManager = pmm_mod.PhysicalMemoryManager;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;

extern const _kernel_base_vaddr: u8;
extern const _kernel_end: u8;

const VMM_ADDR_SPACE_PML4_SLOT = 510;

export fn kmain(
    stack_top_vaddr: u64,
    magic: u32,
    mbi_paddr: u32,
) callconv(.c) void {
    vga.initialize(.White, .Black);

    if (magic != multiboot.MAGIC) {
        @panic("Not a multiboot compliant boot");
    }

    const kernel_base_vaddr: u64 = @intCast(@intFromPtr(&_kernel_base_vaddr));
    const kernel_end: u64 = @intCast(@intFromPtr(&_kernel_end));

    const mbi_vaddr: u64 = kernel_base_vaddr + mbi_paddr;
    const mbi: *const multiboot.MultibootInfo = @ptrFromInt(mbi_vaddr);

    if (!multiboot.checkFlag(mbi.flags, 6)) {
        @panic("Mmap_* are invalid!");
    }

    var memory_regions_buffer: [multiboot.MAX_REGIONS]multiboot.MemoryRegion = undefined;
    const memory_regions: []multiboot.MemoryRegion = multiboot.parseMemoryMap(mbi, &memory_regions_buffer);
    var largest_available_region: multiboot.MemoryRegion = .{
        .addr = 0,
        .len = 0,
        .region_type = multiboot.MemoryRegionType.Available,
    };
    for (memory_regions) |region| {
        if (region.region_type != multiboot.MemoryRegionType.Available) {
            continue;
        }
        if (region.len > largest_available_region.len) {
            largest_available_region = region;
        }
    }
    if (largest_available_region.len == 0) {
        @panic("Failed to find suitable memory region in mmap!");
    }

    const region_end_paddr = largest_available_region.addr + largest_available_region.len;
    const region_end_vaddr = region_end_paddr + kernel_base_vaddr;
    const useable_region_start_paddr = kernel_end - kernel_base_vaddr;
    const useable_region_start_vaddr = kernel_end;

    var bump_allocator = BumpAllocator.init(
        useable_region_start_vaddr,
        region_end_vaddr,
    );
    const bump_alloc_iface = bump_allocator.allocator();

    const page4K = @intFromEnum(paging.PageSize.Page4K);
    const page2M = @intFromEnum(paging.PageSize.Page2M);
    const pml4_paddr = paging.read_cr3();
    const pml4_vaddr = pml4_paddr + kernel_base_vaddr;
    const aligned_end_paddr = std.mem.alignBackward(
        u64,
        region_end_paddr,
        page4K,
    );
    var current_paddr = std.mem.alignForward(
        u64,
        useable_region_start_paddr,
        page4K,
    );
    while (current_paddr < aligned_end_paddr) {
        const page_size = blk: {
            const remaining_bytes = aligned_end_paddr - current_paddr;
            const page_2M_fits = std.mem.isAligned(current_paddr, page2M) and remaining_bytes >= page2M;
            const page_4K_fits = std.mem.isAligned(current_paddr, page4K) and remaining_bytes >= page4K;
            if (page_2M_fits) {
                break :blk page2M;
            } else if (page_4K_fits) {
                break :blk page4K;
            }
            @panic("Invalid paddr alignment when initializing physmap!");
        };
        paging.mapPage(
            @ptrFromInt(pml4_vaddr),
            current_paddr,
            current_paddr + kernel_base_vaddr,
            paging.RW.ReadWrite,
            paging.User.Supervisor,
            @enumFromInt(page_size),
            bump_alloc_iface,
        );
        current_paddr += page_size;
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
    const vmm_start_vaddr = paging.pml4SlotBase(VMM_ADDR_SPACE_PML4_SLOT);
    const vmm_end_vaddr = vmm_start_vaddr + pml4_slot_size;

    var vmm_bump_allocator = BumpAllocator.init(vmm_start_vaddr, vmm_end_vaddr);
    const vmm_bump_alloc_iface = vmm_bump_allocator.allocator();

    vmm_mod.global_vmm = VirtualMemoryManager.init(vmm_bump_alloc_iface);
    const vmm_iface = vmm_mod.global_vmm.?.allocator();

    const heap_addr_space_size = pml4_slot_size / 2;
    const heap_tree_addr_space_size = page1G;

    const heap_addr_space_slice = vmm_iface.alloc(
        u8,
        heap_addr_space_size,
    ) catch @panic("VMM doesn't have enough address space for heap allocator!");
    const heap_tree_addr_space_slice = vmm_iface.alloc(
        u8,
        heap_tree_addr_space_size,
    ) catch @panic("VMM Doesn't have enough address space for heap tree allocator!");

    const heap_addr_space_start = @intFromPtr(heap_addr_space_slice.ptr);
    const heap_addr_space_end = heap_addr_space_start + heap_addr_space_size;

    const heap_tree_addr_space_start = @intFromPtr(heap_tree_addr_space_slice.ptr);
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

    while (true) {
        asm volatile ("hlt");
    }
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
    while (true) {
        asm volatile ("hlt");
    }
}
