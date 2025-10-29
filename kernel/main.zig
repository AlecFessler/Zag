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
const range = zag.math.range;

const BuddyAllocator = zag.memory.BuddyAllocator.BuddyAllocator;
const BumpAllocator = zag.memory.BumpAllocator.BumpAllocator;
const HeapAllocator = zag.memory.HeapAllocator.HeapAllocator;
const HeapTreeAllocator = zag.memory.HeapAllocator.TreeAllocator;
const PAddr = paging.PAddr;
const VAddr = paging.VAddr;
const PhysicalMemoryManager = pmm_mod.PhysicalMemoryManager;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;
const Range = range.Range;

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
        \\movq %%rsp, %%rbp
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

    var smallest_addr_region = boot_defs.MMapEntry{
        .start_paddr = std.math.maxInt(u64),
        .num_pages = 0,
        .type = .free,
    };
    var largest_addr_free_region = boot_defs.MMapEntry{
        .start_paddr = 0,
        .num_pages = 0,
        .type = .free,
    };
    var largest_free_region = boot_defs.MMapEntry{
        .start_paddr = 0,
        .num_pages = 0,
        .type = .free,
    };
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
    const bump_alloc_end_phys = PAddr.fromInt(largest_free_region.start_paddr + largest_free_region.num_pages * PAGE4K);
    var bump_allocator = BumpAllocator.init(
        bump_alloc_start_phys.addr,
        bump_alloc_end_phys.addr,
    );
    var bump_alloc_iface: ?std.mem.Allocator = bump_allocator.allocator();

    const pml4_paddr = PAddr.fromInt(paging.read_cr3().addr & ~@as(u64, 0xfff));
    const pml4_vaddr = VAddr.fromPAddr(pml4_paddr, .identity);

    paging.mapPage(
        @ptrFromInt(pml4_vaddr.addr),
        pml4_paddr,
        VAddr.fromPAddr(pml4_paddr, .physmap),
        .ReadWrite,
        true,
        .Supervisor,
        .Page4K,
        .identity,
        bump_alloc_iface.?,
    );

    for (mmap) |entry| {
        if (entry.type != .free) continue;
        const entry_range: Range = .{
            .start = entry.start_paddr,
            .end = entry.start_paddr + entry.num_pages * PAGE4K,
        };
        paging.physMapRegion(
            pml4_vaddr,
            PAddr.fromInt(entry_range.start),
            PAddr.fromInt(entry_range.end),
            bump_alloc_iface.?,
        );
    }

    const bump_alloc_start_virt = VAddr.fromPAddr(bump_alloc_start_phys, .physmap);
    const bump_alloc_free_virt = VAddr.fromPAddr(PAddr.fromInt(bump_allocator.free_addr), .physmap);
    const bump_alloc_end_virt = VAddr.fromPAddr(bump_alloc_end_phys, .physmap);
    bump_allocator.start_addr = bump_alloc_start_virt.addr;
    bump_allocator.free_addr = bump_alloc_free_virt.addr;
    bump_allocator.end_addr = bump_alloc_end_virt.addr;

    const ksyms_bytes: []const u8 = boot_info.ksyms.ptr[0..boot_info.ksyms.len];
    try zag.panic.initSymbolsFromSlice(ksyms_bytes, bump_alloc_iface.?);

    paging.dropIdentityMap();

    const buddy_alloc_start_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignForward(
            u64,
            smallest_addr_region.start_paddr,
            PAGE4K,
        )),
        .physmap,
    );
    const buddy_alloc_end_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignBackward(
            u64,
            largest_addr_free_region.start_paddr + largest_addr_free_region.num_pages * PAGE4K,
            PAGE4K,
        )),
        .physmap,
    );
    var buddy_allocator = try BuddyAllocator.init(
        buddy_alloc_start_virt.addr,
        buddy_alloc_end_virt.addr,
        bump_alloc_iface.?,
    );
    const buddy_alloc_iface = buddy_allocator.allocator();
    bump_alloc_iface = null;

    for (mmap) |entry| {
        if (entry.type != .free) continue;

        const entry_start_virt = VAddr.fromPAddr(
            PAddr.fromInt(entry.start_paddr),
            .physmap,
        );
        const entry_end_virt = VAddr.fromPAddr(
            PAddr.fromInt(entry.start_paddr + entry.num_pages * PAGE4K),
            .physmap,
        );
        const entry_range: Range = .{
            .start = entry_start_virt.addr,
            .end = entry_end_virt.addr,
        };

        const bump_alloc_range: Range = .{
            .start = bump_allocator.start_addr,
            .end = bump_allocator.free_addr,
        };

        const null_page_start_virt = VAddr.fromPAddr(
            PAddr.fromInt(0),
            .physmap,
        );
        const null_page_end_virt = VAddr.fromPAddr(
            PAddr.fromInt(PAGE4K),
            .physmap,
        );
        const null_page_range: Range = .{
            .start = null_page_start_virt.addr,
            .end = null_page_end_virt.addr,
        };

        var useable_range: Range = undefined;
        if (entry_range.overlapsWith(bump_alloc_range)) {
            useable_range = entry_range.removeOverlap(bump_alloc_range);
        } else if (entry_range.overlapsWith(null_page_range)) {
            useable_range = entry_range.removeOverlap(null_page_range);
        } else {
            useable_range = entry_range;
        }

        buddy_allocator.addRegion(
            useable_range.start,
            useable_range.end,
        );
    }

    pmm_mod.global_pmm = PhysicalMemoryManager.init(buddy_alloc_iface);

    const vmm_start_virt = paging.pml4SlotBase(@intFromEnum(paging.AddressSpace.kvmm));
    const vmm_end_virt = VAddr.fromInt(vmm_start_virt.addr + PAGE1G * paging.PAGE_TABLE_SIZE);
    vmm_mod.global_vmm = VirtualMemoryManager.init(
        vmm_start_virt,
        vmm_end_virt,
    );
    var vmm = &vmm_mod.global_vmm.?;

    const heap_vaddr_space_start = try vmm.reserve(PAGE1G * 256, std.mem.Alignment.fromByteUnits(PAGE4K));
    const heap_vaddr_space_end = VAddr.fromInt(heap_vaddr_space_start.addr + PAGE1G * 256);

    const heap_tree_vaddr_space_start = try vmm.reserve(PAGE1G, std.mem.Alignment.fromByteUnits(PAGE4K));
    const heap_tree_vaddr_space_end = VAddr.fromInt(heap_tree_vaddr_space_start.addr + PAGE1G);

    var heap_tree_backing_allocator = BumpAllocator.init(
        heap_tree_vaddr_space_start.addr,
        heap_tree_vaddr_space_end.addr,
    );
    const heap_tree_backing_allocator_iface = heap_tree_backing_allocator.allocator();
    var heap_tree_allocator = try HeapTreeAllocator.init(heap_tree_backing_allocator_iface);

    var heap_allocator = HeapAllocator.init(
        heap_vaddr_space_start.addr,
        heap_vaddr_space_end.addr,
        &heap_tree_allocator,
    );
    const heap_allocator_iface = heap_allocator.allocator();
    _ = heap_allocator_iface;

    cpu.halt();
}
