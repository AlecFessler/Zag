const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const std = @import("std");

pub const VectorKind = enum {
    exception,
    external,
    software,
};
pub const VectorAck = enum {
    none,
    lapic,
};

const Handler = *const fn (*cpu.Context) void;

const VectorEntry = struct {
    handler: ?Handler = null,
    kind: VectorKind = .external,
    ack: VectorAck = .none,
};

const PUSHES_ERR = blk: {
    var a: [256]bool = .{false} ** 256;
    a[8] = true;
    a[10] = true;
    a[11] = true;
    a[12] = true;
    a[13] = true;
    a[14] = true;
    a[17] = true;
    a[20] = true;
    a[30] = true;
    break :blk a;
};

pub const STUBS: [256]idt.interruptHandler = blk: {
    var arr: [256]idt.interruptHandler = undefined;
    for (0..256) |i| {
        arr[i] = getInterruptStub(i, PUSHES_ERR[i]);
    }
    break :blk arr;
};

const X2APIC_EOI_MSR = 0x80B;

var vector_table: [256]VectorEntry = .{VectorEntry{}} ** 256;

pub fn registerException(vector: u8, handler: Handler) void {
    registerVector(vector, handler, .exception, .none);
}

pub fn registerSoftware(vector: u8, handler: Handler) void {
    registerVector(vector, handler, .software, .none);
}

pub fn registerExternalLapic(vector: u8, handler: Handler) void {
    registerVector(vector, handler, .external, .lapic);
}

fn registerVector(
    vector: u8,
    handler: Handler,
    kind: VectorKind,
    ack: VectorAck,
) void {
    std.debug.assert(vector_table[vector].handler == null);
    vector_table[vector] = .{
        .handler = handler,
        .kind = kind,
        .ack = ack,
    };
}

pub fn getInterruptStub(comptime int_num: u8, comptime pushes_err: bool) idt.interruptHandler {
    return struct {
        fn stub() callconv(.naked) void {
            if (pushes_err) {
                asm volatile (
                    \\pushq %[num]
                    \\jmp commonInterruptStub
                    :
                    : [num] "i" (@as(u64, int_num)),
                );
            } else {
                asm volatile (
                    \\pushq $0
                    \\pushq %[num]
                    \\jmp commonInterruptStub
                    :
                    : [num] "i" (@as(u64, int_num)),
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
        ::: .{ .memory = true, .cc = true });
}

export fn dispatchInterrupt(ctx: *cpu.Context) void {
    if (vector_table[ctx.int_num].handler) |h| {
        h(ctx);
        if (vector_table[@intCast(ctx.int_num)].ack == .lapic) {
            cpu.wrmsr(X2APIC_EOI_MSR, 0); // eoi
        }
        return;
    }
    @panic("Unhandled interrupt!");
}
