const std = @import("std");

const vga = @import("arch/x86/vga.zig");

extern const _kernel_vma: u8;
extern const _kernel_end: u8;

export fn kmain(
    magic: u32,
    mbi_paddr: u32,
) callconv(.c) void {
    vga.initialize(.White, .Black);

    const kernel_vma = @intFromPtr(&_kernel_vma);
    const kernel_end = @intFromPtr(&_kernel_end);

    const mbi_vaddr: u64 = kernel_vma + mbi_paddr;
    if (magic != 0x2BADB002) {
        @panic("Not a multiboot compliant boot");
    }

    vga.print("Mbi vaddr {X}\nKernel vma {X}\nKernel end {X}\n", .{
        mbi_vaddr,
        kernel_vma,
        kernel_end,
    });

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
    vga.setColor(.White, .Blue);
    vga.print("KERNEL PANIC: {s}\n", .{msg});
    while (true) {
        asm volatile ("hlt");
    }
}
