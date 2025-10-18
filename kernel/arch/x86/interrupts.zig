//! Interrupt stubs and dispatch for x86-64.
//!
//! Provides a common naked stub that saves/restores registers, routes to the
//! correct handler, and returns with `iretq`. Also exposes a comptime factory
//! for per-vector stubs that push the expected error code layout.

const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const irq = @import("irq.zig");
const isr = @import("isr.zig");
const std = @import("std");

/// CPU context captured on interrupt entry (matches common stub push order).
pub const InterruptContext = packed struct {
    /// General registers saved by the common stub.
    regs: cpu.Registers,
    /// Interrupt vector number (pushed by per-vector stub).
    int_num: u64,
    /// Error code (real or synthetic 0 depending on vector).
    err_code: u64,
    /// Saved instruction pointer.
    rip: u64,
    /// Saved code segment selector.
    cs: u64,
    /// Saved RFLAGS.
    rflags: u64,
    /// Saved stack pointer.
    rsp: u64,
    /// Saved stack segment selector.
    ss: u64,
};

/// Generates a naked interrupt stub for `int_num`.
///
/// Arguments:
/// - `int_num`: interrupt vector (0..255)
/// - `pushes_err`: whether the CPU pushes an error code for this vector
///
/// Returns:
/// - `idt.interruptHandler`: pointer to a naked stub that pushes `(err_code,int_num)`
///   to match `InterruptContext`, then jumps to `commonInterruptStub`.
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

/// Common naked entry used by all interrupt gates.
///
/// Saves GPRs, builds an `InterruptContext` on the stack, calls
/// `dispatchInterrupt(ctx)` with `%rdi = %rsp`, restores state, and returns via
/// `iretq`. Must be installed behind an IDT gate pointing at this symbol.
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

/// Routes an interrupt to the appropriate handler table.
///
/// Arguments:
/// - `ctx`: pointer to the interrupt context built by the stub.
export fn dispatchInterrupt(ctx: *InterruptContext) void {
    if (ctx.int_num < isr.NUM_ISR_ENTRIES or ctx.int_num == isr.SYSCALL_INT_VECTOR) {
        isr.dispatchIsr(ctx);
    } else {
        irq.dispatchIrq(ctx);
    }
}
