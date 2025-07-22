//! Kernel entry point and early initialization routines.
//!
//! This module defines `kmain`, the entry point for Multiboot v1, and the kernel's panic handler. It sets up memory allocators, page tables, and basic console output before entering idle state.

const std = @import("std");

const console = @import("console.zig");
const bumpalloc = @import("memory/bump_allocator.zig");
const memoryregionmap = @import("memory/memory_region_map.zig");
const multiboot = @import("arch/x86_64/multiboot.zig");
const physmemmgr = @import("memory/physical_memory_manager.zig");
const virtmemmgr = @import("memory/virtual_memory_manager.zig");

const BumpAllocator = bumpalloc.BumpAllocator;
const MemoryRegionMap = memoryregionmap.MemoryRegionMap;
const MemoryRegionType = multiboot.MemoryRegionType;
const MultibootInfo = multiboot.MultibootInfo;
const PhysicalMemoryManager = physmemmgr.PhysicalMemoryManager;
const VirtualMemoryManager = virtmemmgr.VirtualMemoryManager;

extern const _kernel_end: u8;
/// Kernel entry point for Multiboot v1 bootloaders.
///
/// - `magic`: Magic number passed by the bootloader. Should be `0x2BADB002` for Multiboot v1.
/// - `info_ptr`: Physical address of the `MultibootInfo` structure.
///
/// For now, this function assumes a Multiboot v1-compliant environment and performs basic
/// setup of early memory allocators and page tables before halting.
export fn kmain(
    magic: u32,
    info_ptr: u32,
) callconv(.C) void {
    console.initialize(.LightGray, .Black);

    if (magic != 0x2BADB002) {
        console.print("Not a multiboot compliant boot", .{});
        while (true) {
            asm volatile ("hlt");
        }
    }

    const info: *const MultibootInfo = @ptrFromInt(info_ptr);

    var memory_region_map = MemoryRegionMap.init();
    multiboot.parseMemoryMap(
        info,
        MemoryRegionMap.appendRegion,
        &memory_region_map,
    );

    const available_region = memory_region_map.regions[3];
    const region_start = @intFromPtr(&_kernel_end);
    const region_end = available_region.addr + available_region.len;

    var bump_allocator = BumpAllocator.init(region_start, region_end);
    var bump_alloc_iface = bump_allocator.allocator();

    var pmm = PhysicalMemoryManager.init(&bump_alloc_iface);
    var pmm_alloc_iface = pmm.allocator();

    var vmm = VirtualMemoryManager.init(&pmm_alloc_iface);
    var vmm_alloc_iface = vmm.allocator();

    defer vmm_alloc_iface.deinit();

    const addr = vmm_alloc_iface.alloc(4096, 4096) catch @panic("alloc failed");
    const iaddr = @intFromPtr(addr);

    std.debug.assert(iaddr >= region_start);
    std.debug.assert(iaddr < region_end);
    std.debug.assert(std.mem.isAligned(iaddr, 4096));

    const size = region_end - region_start;
    const sizeM = size / (1024 * 1024);
    const pages = size / 4096;
    console.print("Mapped memory start: {} end: {}, size: {}M, pages: {}\n", .{
        region_start,
        region_end,
        sizeM,
        pages,
    });

    while (true) {
        asm volatile ("hlt");
    }
}

/// Called on unrecoverable errors to display a panic message and halt the system.
///
/// Displays the provided message in white-on-blue and halts the CPU indefinitely.
/// Used in place of `std.debug.panic` in a freestanding kernel environment.
pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    console.setColor(.White, .Blue);
    console.print("KERNEL PANIC: {s}\n", .{msg});
    while (true) {
        asm volatile ("hlt");
    }
}
