const std = @import("std");

const IDTEntry = packed struct {
    isr_addr_low: u16,
    kernel_cs: u16,
    ist: u3, // IST index (0 = no switch)
    _res0: u5 = 0,
    gate_type: u4, // 0xE = interrupt, 0xF = trap
    ss: u1 = 0, // storage-seg (must be 0 for gates)
    dpl: u2,
    present: bool,
    isr_addr_mid: u16,
    isr_addr_high: u32,
    _res1: u32 = 0, // must be zero
};

const IDTRType = packed struct { limit: u16, base: u64 };

var IDT: [256]IDTEntry = undefined;
var idtr: IDTRType = undefined;

fn lidt(ptr: *const IDTRType) void {
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (ptr),
        : .{ .memory = true });
}

fn setIDTEntry(
    vec: u8,
    handler: *const anyopaque,
    kernel_cs: u16,
    ist_index: u3, // 0 = don’t switch; 1..7 = IST entry
    dpl: u2, // 0 for exceptions, 3 if user may invoke
    is_trap_gate: bool, // false = interrupt gate (clears IF), true = trap
) void {
    const addr = @intFromPtr(handler);

    IDT[vec] = .{
        .isr_addr_low = @truncate(addr),
        .kernel_cs = kernel_cs,
        .ist = ist_index,
        .gate_type = if (is_trap_gate) 0xF else 0xE,
        .dpl = dpl,
        .present = true,
        .isr_addr_mid = @truncate(addr >> 16),
        .isr_addr_high = @truncate(addr >> 32),
    };
}

const SavedRegs = packed struct {
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

const ISRContext = packed struct {
    regs: SavedRegs,
    int_no: u64,
    err_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64, // only if privilege change
    ss: u64, // only if privilege change
};

fn read_cr2() u64 {
    var v: u64 = 0;
    asm volatile ("mov %%cr2, %[v]"
        : [v] "=r" (v),
    );
    return v;
}

fn isrCommonStub() callconv(.Naked) void {
    asm volatile (
        "pushq %rax\n\t"
        "pushq %rcx\n\t"
        "pushq %rdx\n\t"
        "pushq %rbx\n\t"
        "pushq %rbp\n\t"
        "pushq %rsi\n\t"
        "pushq %rdi\n\t"
        "pushq %r8\n\t"
        "pushq %r9\n\t"
        "pushq %r10\n\t"
        "pushq %r11\n\t"
        "pushq %r12\n\t"
        "pushq %r13\n\t"
        "pushq %r14\n\t"
        "pushq %r15\n\t"

        "mov %rsp, %rdi\n\t"

        "mov %rsp, %r11\n\t"
        "andq $-16, %rsp\n\t"
        "subq $8, %rsp\n\t"

        "call *%[dispatch]\n\t"

        "addq $8, %rsp\n\t"
        "mov %r11, %rsp\n\t"

        "popq %r15\n\t"
        "popq %r14\n\t"
        "popq %r13\n\t"
        "popq %r12\n\t"
        "popq %r11\n\t"
        "popq %r10\n\t"
        "popq %r9\n\t"
        "popq %r8\n\t"
        "popq %rdi\n\t"
        "popq %rsi\n\t"
        "popq %rbp\n\t"
        "popq %rbx\n\t"
        "popq %rdx\n\t"
        "popq %rcx\n\t"
        "popq %rax\n\t"

        "addq $16, %rsp\n\t"
        "iretq\n\t"
        :
        : [dispatch] "r" (isrDispatch)
        :
    );
}

fn isrDispatch(ctx: *ISRContext) callconv(.C) void {
    _ = ctx;
    const cr2 = if (ctx.int_no == 14) read_cr2() else 0;
    _ = cr2;

    while (true) {
        asm volatile ("hlt");
    }
}

const pushes_error = [_]bool{
    false, false, false, false, false, false, false, false,
    true,  false, true,  true,  true,  true,  false, false,
    false, true,  false, false, false, false, false, false,
    false, false, false, false, false, false, false, false,
};

fn makeIsr(comptime N: u8, comptime has_err: bool) fn () callconv(.Naked) void {
    const S = struct {
        fn stub() callconv(.Naked) void {
            if (has_err) {
                asm volatile (
                    "pushq %[vec]\n\t"
                    "jmp *%[common]\n\t"
                    :
                    : [vec] "r" (@as(usize, N)),
                      [common] "r" (isrCommonStub)
                    :
                );
            } else {
                asm volatile (
                    "pushq $0\n\t"
                    "pushq %[vec]\n\t"
                    "jmp *%[common]\n\t"
                    :
                    : [vec] "r" (@as(usize, N)),
                      [common] "r" (isrCommonStub)
                    :
                );
            }
        }
    };
    return S.stub;
}

const isr_vec = blk: {
    var arr: [32]fn () callconv(.Naked) void = undefined;
    for (0..32) |i| {
        arr[i] = makeIsr(@as(u8, i), pushes_error[i]);
    }
    break :blk arr;
};

pub fn idtInstall(kernel_cs: u16, ist_df: u3) void {
    @memset(IDT[0..], std.mem.zeroes(IDTEntry));

    for (0..32) |i| {
        const ist: u3 = if (i == 8) ist_df else 0; // IST only for #DF
        const trap: bool = (i == 3) or (i == 4); // #BP, #OF
        const dpl: u2 = if (i == 3 or i == 4) 3 else 0; // user-invocable
        setIDTEntry(
            @as(u8, i),
            @ptrCast(isr_vec[i]),
            kernel_cs,
            ist,
            dpl,
            trap,
        );
    }

    idtr = .{
        .limit = @intCast(@sizeOf(@TypeOf(IDT)) - 1),
        .base = @intFromPtr(&IDT),
    };
    lidt(&idtr);
    // Enable interrupts only after PIC/APIC + TSS (with IST stacks) are set up.
}
