const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const elf = zag.utils.elf;
const debug = zag.debug;
const memory = zag.memory.init;
const paging = zag.memory.paging;
const process = zag.sched.process;

const BootInfo = zag.boot.protocol.BootInfo;
const PAddr = zag.memory.address.PAddr;
const ParsedElf = zag.utils.elf.ParsedElf;
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
    try memory.init(boot_info.mmap);
    const heap_allocator = try memory.getHeapAllocator();
    const heap_allocator_iface = heap_allocator.allocator();
    const parsed_elf = try debug.info.init(&elf, boot_info.elf_blob, heap_alloc_iface);
    try arch.parseAcpi(boot_info.xsdp_phys);
    try sched.init();
    arch.halt();
}
