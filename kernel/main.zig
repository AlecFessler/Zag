const std = @import("std");

const bootalloc = @import("memory/bootalloc.zig");
const BootAllocator = bootalloc.BootAllocator;
const console = @import("console.zig");
const multiboot = @import("arch/x86_64/multiboot.zig");
const MultibootInfo = multiboot.MultibootInfo;
const MemoryRegionType = multiboot.MemoryRegionType;

export fn kmain(magic: u32, info_ptr: u32) callconv(.C) void {
    console.initialize(.LightGray, .Black);

    if (magic != 0x2BADB002) {
        console.print("Not a multiboot compliant boot", .{});
        while (true) {
            asm volatile ("hlt");
        }
    }

    const info: *const MultibootInfo = @ptrFromInt(info_ptr);
    multiboot.parseMemoryMap(info, printRegion);

    var boot_allocator = BootAllocator.init();
    const slice = boot_allocator.alloc(4096, 16);
    @memset(slice, 10);
    console.print("Element {}\n", .{slice[0]});

    while (true) {
        asm volatile ("hlt");
    }
}

fn printRegion(addr: u64, len: u64, region_type: MemoryRegionType) void {
    console.print("Region entry, addr: {}, len: {}, type: {s}\n", .{ addr, len, region_type.toString() });
}

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    console.setColor(.White, .Blue);
    console.print("KERNEL PANIC: {s}\n", .{msg});
    while (true) {
        asm volatile ("hlt");
    }
}
