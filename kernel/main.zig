const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const elf = zag.utils.elf;
const memory = zag.memory.init;

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
                : .{ .rsp = true, .rbp = true, .rdi = true }
            );
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

    // need to create sched code so you can make a vmm reservation
    // and then create a heap allocator to parse dwarf debug info

    const heap_alloc_iface = heap_allocator.allocator();

    var parsed_elf: ParsedElf = undefined;
    const elf_ptr_phys = PAddr.fromInt(@intFromPtr(boot_info.elf_blob.ptr));
    const elf_ptr_virt = VAddr.fromPAddr(elf_ptr_phys, null);
    const elf_ptr: [*]u8 = @ptrFromInt(elf_ptr_virt.addr);
    const elf_bytes = elf_ptr[0..boot_info.elf_blob.len];
    try elf.parseElf(&parsed_elf, elf_bytes);
    try parsed_elf.dwarf.open(heap_alloc_iface);
    zag.panic.debug_info = &parsed_elf.dwarf;

    //try arch.parseAcpi(boot_info.xsdp_phys);
    arch.halt();
}
