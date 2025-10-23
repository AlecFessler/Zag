pub const containers = @import("containers/containers.zig");
pub const memory = @import("memory/memory.zig");
pub const x86 = @import("arch/x86/x86.zig");

const boot_defs = @import("boot_defs");
const cpu = x86.Cpu;
const serial = x86.Serial;

extern const __stackguard_lower: [*]const u8;

export fn kEntry(boot_info: boot_defs.BootInfo) noreturn {
    asm volatile (
        \\movq %[new_stack], %%rsp
        :
        : [new_stack] "r" (@intFromPtr(&__stackguard_lower) - 0x10),
    );
    kMain(boot_info) catch {
        @panic("Exiting...");
    };
    unreachable;
}

fn kMain(boot_info: boot_defs.BootInfo) !void {
    _ = boot_info;
    serial.init(.com1, 115200);
    serial.print("Hello from Zag!\n", .{});
    cpu.halt();
}
