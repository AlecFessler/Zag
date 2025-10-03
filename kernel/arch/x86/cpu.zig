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

pub fn read_cr2() u64 {
    var v: u64 = 0;
    asm volatile ("mov %%cr2, %[v]"
        : [v] "=r" (v),
    );
    return v;
}

pub fn halt() noreturn {
    while (true) {
        asm volatile ("hlt");
    }
}
