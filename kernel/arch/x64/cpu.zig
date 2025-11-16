const zag = @import("zag");

pub const PrivilegeLevel = enum(u2) {
    ring_0 = 0x0,
    ring_3 = 0x3,
};

pub fn halt() noreturn {
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn readCr3() u64 {
    var value: u64 = 0;
    asm volatile ("mov %%cr3, %[out]"
        : [out] "=r" (value),
    );
    return value;
}

pub fn writeCr3(value: u64) void {
    asm volatile ("mov %[val], %%cr3"
        :
        : [val] "r" (value),
    );
}

pub fn inb(port: u16) u8 {
    return asm volatile (
        \\inb %[port], %[ret]
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
        : .{.dx = true}
    );
}

pub fn outb(value: u8, port: u16) void {
    asm volatile (
        \\outb %[value], %[port]
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
        : .{.dx = true}
    );
}

pub fn lgdt(desc: *const anyopaque) void {
    asm volatile (
        \\lgdt (%[ptr])
        :
        : [ptr] "r" (desc),
    );
}

pub fn ltr(sel: u16) void {
    asm volatile (
        \\mov %[s], %%ax
        \\ltr %%ax
        :
        : [s] "ir" (sel),
    );
}

pub fn lidt(desc: *const anyopaque) void {
    asm volatile ("lidt (%[ptr])"
        :
        : [ptr] "r" (desc)
    );
}

pub fn wrmsr(msr: u32, value: u64) void {
    const lo: u32 = @truncate(value);
    const hi: u32 = @truncate(value >> 32);
    asm volatile (
        \\wrmsr
        :
        : [msr] "{ecx}" (msr),
          [lo] "{eax}" (lo),
          [hi] "{edx}" (hi),
    );
}

pub fn rdmsr(msr: u32) u64 {
    var lo: u32 = 0;
    var hi: u32 = 0;
    asm volatile (
        \\rdmsr
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, hi) << 32) | lo;
}
