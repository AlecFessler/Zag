const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const irq = @import("irq.zig");
const isr = @import("isr.zig");
const std = @import("std");

pub const InterruptContext = packed struct {
    regs: cpu.Registers,
    int_num: u64,
    err_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

pub fn getInterruptStub(comptime int_num: u8, comptime pushes_err: bool) idt.interruptHandler {
    return struct {
        fn stub() callconv(.naked) void {
            if (pushes_err) {
                asm volatile (
                    \\pushq %[num]
                    \\jmp commonInterruptStub
                    :
                    : [num] "i" (@as(usize, int_num))
                );
            } else {
                asm volatile (
                    \\pushq $0
                    \\pushq %[num]
                    \\jmp commonInterruptStub
                    :
                    : [num] "i" (@as(usize, int_num))
                );
            }
        }
    }.stub;
}

export fn commonInterruptStub() callconv(.naked) void {
    asm volatile (
        \\pushq %rax
        \\pushq %rcx
        \\pushq %rdx
        \\pushq %rbx
        \\pushq %rbp
        \\pushq %rsi
        \\pushq %rdi
        \\pushq %r8
        \\pushq %r9
        \\pushq %r10
        \\pushq %r11
        \\pushq %r12
        \\pushq %r13
        \\pushq %r14
        \\pushq %r15
        \\
        \\mov %rsp, %rdi
        \\call dispatchInterrupt
        \\
        \\popq %r15
        \\popq %r14
        \\popq %r13
        \\popq %r12
        \\popq %r11
        \\popq %r10
        \\popq %r9
        \\popq %r8
        \\popq %rdi
        \\popq %rsi
        \\popq %rbp
        \\popq %rbx
        \\popq %rdx
        \\popq %rcx
        \\popq %rax
        \\
        \\addq $16, %rsp
        \\iretq
        :
        :
        : .{ .memory = true, .cc = true }
    );
}

export fn dispatchInterrupt(ctx: *InterruptContext) void {
    if (ctx.int_num < isr.NUM_ISR_ENTRIES or ctx.int_num == isr.SYSCALL_INT_VECTOR) {
        isr.dispatchIsr(ctx);
    } else {
        irq.dispatchIrq(ctx);
    }
}
