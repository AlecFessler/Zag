const std = @import("std");

const console = @import("arch/x86/vga.zig");

extern const _kernel_end: u8;

export fn kmain(
    magic: u32,
    info_ptr: u32,
) callconv(.c) void {
    _ = info_ptr;
    if (magic != 0x2BADB002) {
        @panic("Not a multiboot compliant boot");
    }

    console.initialize(.White, .Black);
    console.print("hello world", .{});

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
