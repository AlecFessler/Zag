//! Kernel entry point and early initialization routines.
//!
//! This module defines `kmain`, the entry point for Multiboot v1, and the kernel's panic handler. It sets up memory allocators, page tables, and basic console output before entering idle state.

const std = @import("std");

const console = @import("console.zig");
const bumpalloc = @import("memory/bump_allocator.zig");
const multiboot = @import("arch/x86_64/multiboot.zig");
const physmemmgr = @import("memory/physical_memory_manager.zig");
const virtmemmgr = @import("memory/virtual_memory_manager.zig");

const BumpAllocator = bumpalloc.BumpAllocator;
const MemoryRegion = multiboot.MemoryRegion;
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
    var memory_regions_array: [multiboot.MAX_REGIONS]MemoryRegion = undefined;
    const memory_regions: []MemoryRegion = multiboot.parseMemoryMap(info, &memory_regions_array);
    const available_region = memory_regions[3];

    const kernel_end = @intFromPtr(&_kernel_end);
    var bump_allocator = BumpAllocator.init(
        kernel_end,
        available_region.addr + available_region.len,
    );
    var bump_alloc_iface = bump_allocator.allocator();

    var pmm = PhysicalMemoryManager.init(&bump_alloc_iface);
    var pmm_alloc_iface = pmm.allocator();

    var vmm = VirtualMemoryManager.init(&pmm_alloc_iface);
    var vmm_alloc_iface = vmm.allocator();

    const addr = vmm_alloc_iface.alloc(4096, 4096) catch @panic("alloc failed\n");
    const iaddr = @intFromPtr(addr);

    std.debug.assert(iaddr >= kernel_end);
    std.debug.assert(iaddr < available_region.addr + available_region.len);
    std.debug.assert(std.mem.isAligned(iaddr, 4096));

    const sizeM = available_region.len / (1024 * 1024);
    const pages = available_region.len / 4096;
    console.print("Mapped memory start: {} end: {}, size: {}M, pages: {}\n", .{
        kernel_end,
        available_region.addr + available_region.len,
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
