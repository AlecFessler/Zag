const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug = zag.debug;
const memory = zag.memory.init;
const sched = zag.sched.scheduler;

const BootInfo = zag.boot.protocol.BootInfo;

pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    zag.panic.panic(msg, error_return_trace, ret_addr);
}

export fn kEntry(boot_info: *BootInfo) callconv(.{ .x86_64_sysv = .{} }) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\movq %[sp], %%rsp
                \\movq %%rsp, %%rbp
                \\movq %[arg], %%rdi
                \\jmp *%[ktrampoline]
                :
                : [sp] "r" (boot_info.stack_top.addr),
                  [arg] "r" (@intFromPtr(boot_info)),
                  [ktrampoline] "r" (@intFromPtr(&kTrampoline)),
                : .{ .rsp = true, .rbp = true, .rdi = true });
        },
        .aarch64 => {},
        else => unreachable,
    }
    unreachable;
}

export fn kTrampoline(boot_info: *BootInfo) noreturn {
    kMain(boot_info) catch {
        @panic("Exiting...");
    };
    unreachable;
}

fn kMain(boot_info: *BootInfo) !void {
    arch.init();
    try memory.init(boot_info.mmap);
    const suspect: *volatile u64 = @ptrFromInt(0xffffff801fe70000);
    arch.print("after memory.init: {x}\n", .{suspect.*});

    var heap_allocator = try memory.getHeapAllocator();

    arch.print("after getHeapAllocator: {x}\n", .{suspect.*});
    const heap_allocator_iface = heap_allocator.allocator();
    _ = try debug.info.init(boot_info.elf_blob, heap_allocator_iface);
    arch.print("Initialized debug info\n", .{});
    try arch.parseAcpi(boot_info.xsdp_phys);
    try sched.init();
    arch.halt();
}
