const paging = @import("paging.zig");

const VAddr = paging.VAddr;

pub const Registers = packed struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
};

pub fn read_cr2() VAddr {
    var addr: u64 = 0;
    asm volatile ("mov %%cr2, %[addr]"
        : [addr] "=r" (addr),
    );
    return VAddr.fromInt(addr);
}

pub fn halt() noreturn {
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn invlpg(vaddr: VAddr) void {
    asm volatile (
        \\invlpg (%[a])
        :
        : [a] "r" (vaddr.addr)
        : .{ .memory = true }
    );
}

pub fn reloadSegments() void {
    asm volatile (
        \\pushq $0x08
        \\leaq 1f(%%rip), %%rax
        \\pushq %%rax
        \\lretq
        \\1:
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%ax, %%ss
        :
        :
        : .{ .memory = true }
    );
}
