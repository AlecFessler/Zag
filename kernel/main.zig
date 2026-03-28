const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug = zag.debug;
const device_registry = zag.devices.registry;
const memory = zag.memory.init;
const sched = zag.sched.scheduler;

const BootInfo = zag.boot.protocol.BootInfo;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

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
    arch.print("K: memory init\n", .{});
    try memory.init(boot_info.mmap);
    try memory.initHeap();
    _ = try debug.info.init(boot_info.elf_blob, memory.heap_allocator);
    arch.print("K: memory done, firmware tables\n", .{});
    try arch.parseFirmwareTables(boot_info.xsdp_phys);
    if (boot_info.framebuffer.pixel_format != .none and boot_info.framebuffer.base.addr != 0) {
        const fb = &boot_info.framebuffer;
        _ = device_registry.registerDisplayDevice(
            fb.base,
            fb.size,
            @truncate(fb.width),
            @truncate(fb.height),
            @truncate(fb.stride),
            @intFromEnum(fb.pixel_format),
        ) catch {};
        arch.print("K: registered GOP framebuffer {}x{}\n", .{ fb.width, fb.height });
    }
    arch.print("K: sched init\n", .{});
    const rs_phys = PAddr.fromInt(@intFromPtr(boot_info.root_service.ptr));
    const rs_virt = VAddr.fromPAddr(rs_phys, null);
    const rs_ptr: [*]const u8 = @ptrFromInt(rs_virt.addr);
    try sched.globalInit(rs_ptr[0..boot_info.root_service.len]);
    arch.print("K: smp init\n", .{});
    try arch.smpInit();
    arch.print("K: per core init\n", .{});
    sched.perCoreInit();
    arch.halt();
}
