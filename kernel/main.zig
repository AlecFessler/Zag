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
    arch.print("[1] arch.init done\n", .{});

    try memory.init(boot_info.mmap);
    arch.print("[2] memory.init done\n", .{});

    try memory.initHeap();
    arch.print("[3] memory.initHeap done\n", .{});

    _ = try debug.info.init(boot_info.elf_blob, memory.heap_allocator);
    arch.print("[4] debug.info.init done\n", .{});

    try arch.parseFirmwareTables(boot_info.xsdp_phys);
    arch.print("[5] parseFirmwareTables done\n", .{});

    try sched.globalInit();
    arch.print("[6] sched.globalInit done\n", .{});

    try arch.smpInit();
    arch.print("[7] smpInit done\n", .{});

    sched.perCoreInit();
    arch.print("[8] perCoreInit done -- should not reach here\n", .{});

    arch.halt();
}
