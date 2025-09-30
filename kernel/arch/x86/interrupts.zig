const std = @import("std");

const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const isr = @import("isr.zig");

extern fn isrDisptacher(ctx: *InterruptContext) void;
extern fn irqDispatcher(ctx: *InterruptContext) void;

export fn interruptDispatcher(ctx: *InterruptContext) void {
    if (ctx.int_num < isr.NUM_ISR_ENTRIES or ctx.int_num == isr.SYSCALL_INT_VECTOR) {
        isrDispatcher(ctx);
    } else {
        irqDispatcher(ctx);
    }
}

pub const InterruptContext = packed struct {
    regs: cpu.Registers,
    int_num: u64,
    err_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64, // only if privilege change
    ss: u64, // only if privilege change
};

export fn interruptCommonStub() callconv(.Naked) void {
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
        : [dispatch] "r" (interruptDispatcher)
        :
    );
}

pub fn getInterruptStub(comptime int_num: u8, comptime pushes_err: bool) idt.interruptHandler {
    return struct {
        fn stub() callconv(.Naked) void {
            if (pushes_err) {
                asm volatile (
                    "pushq %[num]\n\t"
                    "jmp *%[common]\n\t"
                    :
                    : [num] "r" (@as(usize, int_num)),
                      [common] "r" (interruptCommonStub)
                    :
                );
            } else {
                asm volatile (
                    "pushq $0\n\t"
                    "pushq %[num]\n\t"
                    "jmp *%[common]\n\t"
                    :
                    : [num] "r" (@as(usize, int_num)),
                      [common] "r" (interruptCommonStub)
                    :
                );
            }
        }
    }.stub;
}
