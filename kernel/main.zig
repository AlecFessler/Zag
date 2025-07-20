const std = @import("std");

const bootalloc = @import("memory/boot_allocator.zig");
const console = @import("console.zig");
const multiboot = @import("arch/x86_64/multiboot.zig");
const regionalloc = @import("memory/region_allocator.zig");

const BootAllocator = bootalloc.BootAllocator;
const MultibootInfo = multiboot.MultibootInfo;
const MemoryRegionType = multiboot.MemoryRegionType;
const RegionAllocator = regionalloc.RegionAllocator;

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

    var boot_allocator: BootAllocator = undefined;
    boot_allocator.init();

    var region_allocator = RegionAllocator.init(&boot_allocator.allocator);
    const info: *const MultibootInfo = @ptrFromInt(info_ptr);
    multiboot.parseMemoryMap(
        info,
        RegionAllocator.append_region,
        &region_allocator,
    );

    const base_vaddr = 0xFFFF800000000000;
    region_allocator.initialize_page_tables(base_vaddr);

    console.print("Mapped memory:\n", .{});
    for (0..region_allocator.mapped_count) |i| {
        const mapped = region_allocator.mapped[i];
        const len = mapped.end - mapped.start;
        console.print("Base: {}, Len: {}, Page size: {}\n", .{
            mapped.start,
            len,
            mapped.page_size.size(),
        });
    }

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
    _ = ret_addr;
    console.setColor(.White, .Blue);
    console.print("KERNEL PANIC: {s}\n", .{msg});
    while (true) {
        asm volatile ("hlt");
    }
}
