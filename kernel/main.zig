//! Kernel bootstrap module for Zag.
//!
//! Contains the early entrypoint `kmain` used by the Multiboot bootloader
//! and the kernel-level panic function.

const memory = @import("memory");
const panic_mod = @import("panic.zig");
const std = @import("std");
const x86 = @import("x86");

const bump_alloc = memory.BumpAllocator;
const buddy_alloc = memory.BuddyAllocator;
const cpu = x86.Cpu;
const gdt = x86.Gdt;
const heap_alloc = memory.HeapAllocator;
const idt = x86.Idt;
const interrupts = x86.Interrupts;
const isr = x86.Isr;
const multiboot = x86.Multiboot;
const paging = x86.Paging;
const pmm_mod = memory.PhysicalMemoryManager;
const vga = x86.Vga;
const vmm_mod = memory.VirtualMemoryManager;

const BumpAllocator = bump_alloc.BumpAllocator;
const BuddyAllocator = buddy_alloc.BuddyAllocator;
const HeapAllocator = heap_alloc.HeapAllocator;
const HeapTreeAllocator = heap_alloc.TreeAllocator;
const PAddr = paging.PAddr;
const PhysicalMemoryManager = pmm_mod.PhysicalMemoryManager;
const VAddr = paging.VAddr;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;

extern const _bss_end: u8;
extern const _bss_start: u8;
extern const _data_end: u8;
extern const _data_start: u8;
extern const _kernel_end: u8;
extern const _rodata_end: u8;
extern const _rodata_start: u8;
extern const _text_end: u8;
extern const _text_start: u8;

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
    panic_mod.panic(msg, error_return_trace, ret_addr);
}

/// Kernel entry point called by the Multiboot bootloader.
///
/// Arguments:
/// - `stack_top_vaddr`: virtual address of the stack top
/// - `magic`: multiboot magic number (must equal `multiboot.MAGIC`)
/// - `mbi_addr`: physical address of the multiboot information structure
export fn kmain(
    stack_top_vaddr: u64,
    magic: u32,
    mbi_addr: u32,
) callconv(.c) void {
    vga.initialize(.White, .Black, .kernel);
    vga.clear();

    if (magic != multiboot.MAGIC) {
        @panic("Not a multiboot compliant boot");
    }

    gdt.init(VAddr.fromInt(stack_top_vaddr));
    idt.init();
    isr.init();

    const mbi_paddr = PAddr.fromInt(@intCast(mbi_addr));
    const mbi_vaddr = VAddr.fromPAddr(mbi_paddr, .kernel);
    const mbi = mbi_vaddr.getPtr(*multiboot.MultibootInfo);

    if (!multiboot.checkFlag(mbi.flags, 6)) {
        @panic("Mmap_* are invalid!");
    }

    var memory_regions_buffer: [multiboot.MAX_REGIONS]multiboot.MemoryRegion = undefined;
    const memory_regions: []multiboot.MemoryRegion = multiboot.parseMemoryMap(
        mbi,
        &memory_regions_buffer,
    );

    const kernel_end_vaddr = VAddr.fromInt(@intCast(@intFromPtr(&_kernel_end)));
    const page4K = @intFromEnum(paging.PageSize.Page4K);

    const useable_region_start_vaddr = VAddr.fromInt(std.mem.alignForward(
        u64,
        kernel_end_vaddr.addr,
        page4K,
    ));

    const already_mapped_region_end_paddr = PAddr.fromInt(0x600000);
    const already_mapped_region_end_vaddr = VAddr.fromPAddr(already_mapped_region_end_paddr, .kernel);

    // initially cap bump allocator memory out at what's already mapped
    var bump_allocator = BumpAllocator.init(
        useable_region_start_vaddr.addr,
        already_mapped_region_end_vaddr.addr,
    );
    const bump_alloc_iface = bump_allocator.allocator();

    // save paddrs to remap into new page tables
    const symbol_map_start_kernel_vaddr = VAddr.fromInt(bump_allocator.free_addr);
    const symbol_map_start_paddr = PAddr.fromVAddr(symbol_map_start_kernel_vaddr, .kernel);
    if (multiboot.parseModules(mbi, "kernel.map")) |map_bytes| {
        panic_mod.initSymbolsFromSlice(
            map_bytes,
            bump_alloc_iface,
        ) catch @panic("Failed to initialize symbols map!");
    } else {
        @panic("Symbols map not found!");
    }
    const symbol_map_end_kernel_vaddr = VAddr.fromInt(bump_allocator.free_addr);
    const symbol_map_end_paddr = PAddr.fromVAddr(symbol_map_end_kernel_vaddr, .kernel);

    const new_pml4_mem = bump_alloc_iface.alignedAlloc(
        paging.PageEntry,
        paging.PAGE_ALIGN,
        paging.PAGE_TABLE_SIZE,
    ) catch @panic("Bump allocator failed to allocate new pml4 table!");
    @memset(new_pml4_mem, paging.default_flags);
    const new_pml4_vaddr = VAddr.fromInt(@intFromPtr(new_pml4_mem.ptr));

    // map kernel symbol map into new pml4 at original kernel addresses to preserve internal arraylist pointers
    var current_symbol_map_page_paddr = symbol_map_start_paddr;
    std.debug.assert(std.mem.isAligned(
        symbol_map_start_paddr.addr,
        page4K,
    ));
    while (current_symbol_map_page_paddr.addr < symbol_map_end_paddr.addr) {
        const current_symbol_map_page_vaddr = VAddr.fromPAddr(
            current_symbol_map_page_paddr,
            .kernel,
        );
        paging.mapPage(
            @ptrFromInt(new_pml4_vaddr.addr),
            current_symbol_map_page_paddr,
            current_symbol_map_page_vaddr,
            .Readonly,
            false,
            .Supervisor,
            .Page4K,
            .kernel,
            bump_alloc_iface,
        );

        current_symbol_map_page_paddr.addr += page4K;
    }

    const text_start = VAddr.fromInt(@intCast(@intFromPtr(&_text_start)));
    const text_end = VAddr.fromInt(@intCast(@intFromPtr(&_text_end)));
    const page_aligned_text_end = VAddr.fromInt(std.mem.alignForward(
        u64,
        text_end.addr,
        page4K,
    ));
    const text_pages = (page_aligned_text_end.addr - text_start.addr) / page4K;
    for (0..text_pages) |i| {
        const page_vaddr = VAddr.fromInt(text_start.addr + i * page4K);
        const page_paddr = PAddr.fromVAddr(page_vaddr, .kernel);
        std.debug.assert(page_vaddr.addr < page_aligned_text_end.addr);
        paging.mapPage(
            @ptrFromInt(new_pml4_vaddr.addr),
            page_paddr,
            page_vaddr,
            .Readonly,
            false,
            .Supervisor,
            .Page4K,
            .kernel,
            bump_alloc_iface,
        );
    }

    // Everything from rodata start to data start is mapped as readonly
    // because the linker places linker symbols in another section between this
    // span that comes after rodata_end, so we resolve this by mapping the hole as readonly
    const rodata_start = VAddr.fromInt(@intCast(@intFromPtr(&_rodata_start)));
    const data_start = VAddr.fromInt(@intCast(@intFromPtr(&_data_start)));
    const page_aligned_rodata_end = VAddr.fromInt(std.mem.alignForward(
        u64,
        data_start.addr,
        page4K,
    ));
    const rodata_pages = (page_aligned_rodata_end.addr - rodata_start.addr) / page4K;
    for (0..rodata_pages) |i| {
        const page_vaddr = VAddr.fromInt(rodata_start.addr + i * page4K);
        const page_paddr = PAddr.fromVAddr(page_vaddr, .kernel);
        std.debug.assert(page_vaddr.addr < page_aligned_rodata_end.addr);
        paging.mapPage(
            @ptrFromInt(new_pml4_vaddr.addr),
            page_paddr,
            page_vaddr,
            .Readonly,
            true,
            .Supervisor,
            .Page4K,
            .kernel,
            bump_alloc_iface,
        );
    }

    const data_end = VAddr.fromInt(@intCast(@intFromPtr(&_data_end)));
    const page_aligned_data_end = VAddr.fromInt(std.mem.alignForward(
        u64,
        data_end.addr,
        page4K,
    ));
    const data_pages = (page_aligned_data_end.addr - data_start.addr) / page4K;
    for (0..data_pages) |i| {
        const page_vaddr = VAddr.fromInt(data_start.addr + i * page4K);
        const page_paddr = PAddr.fromVAddr(page_vaddr, .kernel);
        std.debug.assert(page_vaddr.addr < page_aligned_data_end.addr);
        paging.mapPage(
            @ptrFromInt(new_pml4_vaddr.addr),
            page_paddr,
            page_vaddr,
            .ReadWrite,
            true,
            .Supervisor,
            .Page4K,
            .kernel,
            bump_alloc_iface,
        );
    }

    const bss_start = VAddr.fromInt(@intCast(@intFromPtr(&_bss_start)));
    const bss_end = VAddr.fromInt(@intCast(@intFromPtr(&_bss_end)));
    const page_aligned_bss_end = VAddr.fromInt(std.mem.alignForward(
        u64,
        bss_end.addr,
        page4K,
    ));
    const bss_pages = (page_aligned_bss_end.addr - bss_start.addr) / page4K;
    for (0..bss_pages) |i| {
        const page_vaddr = VAddr.fromInt(bss_start.addr + i * page4K);
        const page_paddr = PAddr.fromVAddr(page_vaddr, .kernel);
        std.debug.assert(page_vaddr.addr < page_aligned_bss_end.addr);
        paging.mapPage(
            @ptrFromInt(new_pml4_vaddr.addr),
            page_paddr,
            page_vaddr,
            .ReadWrite,
            true,
            .Supervisor,
            .Page4K,
            .kernel,
            bump_alloc_iface,
        );
    }

    var max_end_paddr = PAddr.fromInt(0);
    for (memory_regions) |region| {
        if (region.region_type != multiboot.MemoryRegionType.Available) continue;

        const kernel_end_paddr = PAddr.fromVAddr(kernel_end_vaddr, .kernel);
        const start_addr = if (kernel_end_paddr.addr > region.addr and kernel_end_paddr.addr < region.addr + region.len) kernel_end_paddr else PAddr.fromInt(region.addr);

        const start_paddr = PAddr.fromInt(std.mem.alignForward(
            u64,
            start_addr.addr,
            page4K,
        ));
        const end_paddr = PAddr.fromInt(std.mem.alignBackward(
            u64,
            region.addr + region.len,
            page4K,
        ));
        if (end_paddr.addr <= start_paddr.addr) continue;
        if (end_paddr.addr > max_end_paddr.addr) max_end_paddr = end_paddr;

        paging.physMapRegion(
            new_pml4_vaddr,
            start_paddr,
            end_paddr,
            bump_alloc_iface,
        );
    }

    const vga_paddr = PAddr.fromInt(0xB8000);
    const vga_vaddr = VAddr.fromPAddr(vga_paddr, .physmap);
    paging.mapPage(
        @ptrFromInt(new_pml4_vaddr.addr),
        vga_paddr,
        vga_vaddr,
        .ReadWrite,
        true,
        .Supervisor,
        .Page4K,
        .kernel,
        bump_alloc_iface,
    );

    // flush tlb
    // after this point pmm and mmio should use .physmap for hhdm type instead of .kernel
    const pml4_paddr = PAddr.fromVAddr(new_pml4_vaddr, .kernel);
    paging.write_cr3(pml4_paddr);

    // reinitialize vga module with text buffer remapped to physmap hhdm
    vga.initialize(.White, .Black, .physmap);

    // remap bump allocator address space to physmap
    bump_allocator.start_addr = VAddr.fromInt(bump_allocator.start_addr).remapHHDMType(.kernel, .physmap).addr;
    bump_allocator.free_addr = VAddr.fromInt(bump_allocator.free_addr).remapHHDMType(.kernel, .physmap).addr;
    // expand bump allocator memory to newly mapped region
    bump_allocator.end_addr = VAddr.fromPAddr(max_end_paddr, .physmap).addr;

    const buddy_metadata_bytes = BuddyAllocator.requiredMemory(
        bump_allocator.free_addr,
        bump_allocator.end_addr,
    );
    const buddy_start_vaddr = VAddr.fromInt(std.mem.alignForward(
        u64,
        bump_allocator.free_addr + buddy_metadata_bytes,
        page4K,
    ));
    const buddy_end_vaddr = VAddr.fromInt(std.mem.alignBackward(
        u64,
        bump_allocator.end_addr,
        page4K,
    ));
    std.debug.assert(buddy_end_vaddr.addr > buddy_start_vaddr.addr);

    var buddy_allocator: BuddyAllocator = BuddyAllocator.init(
        buddy_start_vaddr.addr,
        buddy_end_vaddr.addr,
        bump_alloc_iface,
    ) catch @panic("Failed to allocate memory for buddy allocator!");
    const buddy_alloc_iface = buddy_allocator.allocator();

    pmm_mod.global_pmm = PhysicalMemoryManager.init(buddy_alloc_iface);

    const page1G = @intFromEnum(paging.PageSize.Page1G);
    const pml4_slot_size = page1G * paging.PAGE_TABLE_SIZE;
    const vmm_start_vaddr = paging.pml4SlotBase(@intFromEnum(paging.AddressSpace.kvmm));
    const vmm_end_vaddr = VAddr.fromInt(vmm_start_vaddr.addr + pml4_slot_size);

    vmm_mod.global_vmm = VirtualMemoryManager.init(
        vmm_start_vaddr,
        vmm_end_vaddr,
    );
    var vmm = &vmm_mod.global_vmm.?;

    const heap_vaddr_space_start = vmm.reserve(
        page1G * 256,
        std.mem.Alignment.fromByteUnits(page4K),
    ) catch @panic("VMM doesn't have enough address space for heap allocator!");
    const heap_vaddr_space_end = VAddr.fromInt(heap_vaddr_space_start.addr + page1G * 256);

    const heap_tree_vaddr_space_start = vmm.reserve(
        page1G,
        std.mem.Alignment.fromByteUnits(page4K),
    ) catch @panic("VMM doesn't have enough address space for heap tree allocator!");
    const heap_tree_vaddr_space_end = VAddr.fromInt(heap_tree_vaddr_space_start.addr + page1G);

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
    vga.print("Slice addr {X}", .{@intFromPtr(slice.ptr)});

    cpu.halt();
}
