//! Interrupt dispatch table, vector stubs, and common ISR trampoline.
//!
//! Provides a compile-time table of 256 interrupt stubs, a registry for
//! associating vectors with handlers, and a naked common ISR trampoline that
//! captures CPU state and routes to `dispatchInterrupt`. Supports exceptions,
//! external (e.g., LAPIC) and software vectors, with optional LAPIC EOI.
//! Designed for early bring-up and kernel use.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `VectorAck` – acknowledges source after handler returns (none or LAPIC).
//! - `VectorKind` – categorizes vector origin (exception/external/software).
//! - `VectorEntry` – registry entry holding handler, kind, and ack policy.
//! - `Handler` – function pointer type for interrupt handlers.
//!
//! ## Constants
//! - `STUBS` – array of 256 prebuilt interrupt stubs for the IDT.
//! - `PUSHES_ERR` – table of which vectors push an error code.
//!
//! ## Variables
//! - `vector_table` – registry of installed handlers and metadata by vector.
//!
//! ## Functions
//! - `getInterruptStub` – build a naked ISR stub for a specific vector.
//! - `registerException` – register handler for an exception vector.
//! - `registerExternalLapic` – register handler for an external LAPIC vector.
//! - `registerSoftware` – register handler for a software vector.
//! - `registerVector` – internal helper to populate `vector_table`.
//! - `commonInterruptStubPrologue` – naked common ISR prologue (exported).
//! - `commonInterruptStubEpilogue` – naked common ISR epilogue (exported).
//! - `dumpInterruptFrame` – pretty-print a saved interrupt frame.
//! - `dispatchInterrupt` – looks up handler, invokes it, and issues EOI if needed.

const apic = @import("apic.zig");
const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const serial = @import("serial.zig");
const std = @import("std");

pub const VectorAck = enum {
    none,
    lapic,
};

pub const VectorKind = enum {
    exception,
    external,
    software,
};

const VectorEntry = struct {
    handler: ?Handler = null,
    kind: VectorKind = .external,
    ack: VectorAck = .none,
};

const Handler = *const fn (*cpu.Context) void;

pub const STUBS: [256]idt.interruptHandler = blk: {
    var arr: [256]idt.interruptHandler = undefined;
    for (0..256) |i| {
        arr[i] = getInterruptStub(i, PUSHES_ERR[i]);
    }
    break :blk arr;
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

var vector_table: [256]VectorEntry = .{VectorEntry{}} ** 256;

/// Summary:
/// Returns a naked ISR stub for `int_num` that pushes the vector number and,
/// if `pushes_err` is true, preserves the architecture-pushed error slot
/// before tail-jumping to `commonInterruptStubPrologue`.
///
/// Arguments:
/// - `int_num`: compile-time vector number (0–255).
/// - `pushes_err`: compile-time flag indicating whether the CPU pushes an error code.
///
/// Returns:
/// - `idt.interruptHandler` stub function to place in the IDT.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn getInterruptStub(comptime int_num: u8, comptime pushes_err: bool) idt.interruptHandler {
    return struct {
        fn stub() callconv(.naked) void {
            if (pushes_err) {
                asm volatile (
                    \\pushq %[num]
                    \\jmp commonInterruptStubPrologue
                    :
                    : [num] "i" (@as(u64, int_num)),
                );
            } else {
                asm volatile (
                    \\pushq $0
                    \\pushq %[num]
                    \\jmp commonInterruptStubPrologue
                    :
                    : [num] "i" (@as(u64, int_num)),
                );
            }
        }
    }.stub;
}

/// Summary:
/// Registers a handler for an exception vector in the dispatch table.
/// No acknowledgement is issued after the handler returns.
///
/// Arguments:
/// - `vector`: exception vector number (0–31 typically).
/// - `handler`: function pointer taking `*cpu.Context`.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn registerException(vector: u8, handler: Handler) void {
    registerVector(vector, handler, .exception, .none);
}

/// Summary:
/// Registers a handler for an external LAPIC-delivered interrupt and configures
/// the dispatcher to issue LAPIC EOI after the handler returns.
///
/// Arguments:
/// - `vector`: external interrupt vector number (typically 32+).
/// - `handler`: function pointer taking `*cpu.Context`.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn registerExternalLapic(vector: u8, handler: Handler) void {
    registerVector(vector, handler, .external, .lapic);
}

/// Summary:
/// Registers a handler for a software-generated interrupt with no acknowledgement.
///
/// Arguments:
/// - `vector`: software interrupt vector number.
/// - `handler`: function pointer taking `*cpu.Context`.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn registerSoftware(vector: u8, handler: Handler) void {
    registerVector(vector, handler, .software, .none);
}

/// Summary:
/// Internal helper that writes a new `VectorEntry` into `vector_table`.
/// Ensures a vector is registered at most once.
///
/// Arguments:
/// - `vector`: vector number to register.
/// - `handler`: function pointer taking `*cpu.Context`.
/// - `kind`: classification of the vector origin.
/// - `ack`: post-handler acknowledgement policy.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics if the vector already has a registered handler.
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

/// Summary:
/// Common naked ISR trampoline exported for all stubs. Saves caller registers
/// to build a `cpu.Context`, calls `dispatchInterrupt`, then tail-jumps to the
/// epilogue which restores registers and returns with `iretq`.
///
/// Arguments:
/// - None.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
export fn commonInterruptStubPrologue() callconv(.naked) void {
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
        \\ jmp commonInterruptStubEpilogue
        ::: .{ .memory = true, .cc = true });
}

/// Summary:
/// Common ISR epilogue: restores registers, discards `int_num` and `err_code`,
/// and returns to interrupted context with `iretq`.
///
/// Arguments:
/// - None.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
export fn commonInterruptStubEpilogue() callconv(.naked) void {
    asm volatile (
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

/// Summary:
/// Pretty-prints the interrupt frame saved by the common stub.
///
/// Arguments:
/// - `ctx`: pointer to the saved `cpu.Context`.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn dumpInterruptFrame(ctx: *cpu.Context) void {
    const words: [*]const u64 = @ptrCast(ctx);

    serial.print("\n=== INTERRUPT FRAME ===\n", .{});
    serial.print("ctx @ {x}\n\n", .{ @intFromPtr(ctx) });

    serial.print("Regs (pushed by stub):\n", .{});
    const reg_names = [_][]const u8{
        "r15","r14","r13","r12",
        "r11","r10","r9 ","r8 ",
        "rdi","rsi","rbp","rbx",
        "rdx","rcx","rax","INT",
    };

    var i: usize = 0;
    while (i < 16) : (i += 4) {
        serial.print(
            "{s}={x:016}  {s}={x:016}  {s}={x:016}  {s}={x:016}\n",
            .{
                reg_names[i],   words[i],
                reg_names[i+1], words[i+1],
                reg_names[i+2], words[i+2],
                reg_names[i+3], words[i+3],
            },
        );
    }
    serial.print("\n", .{});

    serial.print("err_code={x:016}\n", .{ words[16] });
    serial.print("RIP      ={x:016}\n", .{ words[17] });
    serial.print("CS       ={x:016}\n", .{ words[18] });
    serial.print("RFLAGS   ={x:016}\n", .{ words[19] });

    if ((words[18] & 3) == 3) {
        serial.print("RSP      ={x:016}\n", .{ words[20] });
        serial.print("SS       ={x:016}\n", .{ words[21] });
    } else {
        serial.print("(kernel CPL: no RSP/SS on frame)\n", .{});
    }

    serial.print("=== END FRAME ===\n\n", .{});
}

/// Summary:
/// Dispatches to the registered handler for `ctx.int_num`, then issues LAPIC
/// EOI if the vector's acknowledgement policy requires it.
///
/// Arguments:
/// - `ctx`: saved register context captured by the common stub.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics if no handler is registered for the vector.
export fn dispatchInterrupt(ctx: *cpu.Context) void {
    if (vector_table[ctx.int_num].handler) |h| {
        h(ctx);
        if (vector_table[@intCast(ctx.int_num)].ack == .lapic) {
            apic.endOfInterrupt();
        }
        return;
    }
    dumpInterruptFrame(ctx);
    @panic("Unhandled interrupt!");
}
