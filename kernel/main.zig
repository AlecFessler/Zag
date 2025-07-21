//! Kernel entry point and early initialization routines.
//!
//! This module defines `kmain`, the entry point for Multiboot v1, and the kernel's panic handler.
//! It sets up memory allocators, page tables, and basic console output before entering idle state.

const std = @import("std");

const bootalloc = @import("memory/boot_allocator.zig");
const console = @import("console.zig");
const multiboot = @import("arch/x86_64/multiboot.zig");
const regionalloc = @import("memory/region_allocator.zig");

const BootAllocator = bootalloc.BootAllocator;
const MultibootInfo = multiboot.MultibootInfo;
const MemoryRegionType = multiboot.MemoryRegionType;
const RegionAllocator = regionalloc.RegionAllocator;

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

    var boot_allocator: BootAllocator = undefined;
    boot_allocator.init();
    var region_allocator = RegionAllocator.init(&boot_allocator.allocator);

    multiboot.parseMemoryMap(
        info,
        RegionAllocator.appendRegion,
        &region_allocator,
    );

    const base_vaddr = 0;
    //const base_vaddr = 0xFFFF800000000000;
    region_allocator.initializePageTables(base_vaddr);

    const size = region_allocator.mapped_end - region_allocator.mapped_start;
    const sizeM = size / (1024 * 1024);
    const pages = size / 4096;
    console.print("Mapped memory start: {} end: {}, size: {}M, pages: {}\n", .{
        region_allocator.mapped_start,
        region_allocator.mapped_end,
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
