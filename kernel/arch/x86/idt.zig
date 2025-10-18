//! IDT setup and interrupt gate utilities for x86-64.
//!
//! Defines IDT entry formats, helpers for opening gates, and installs the IDT
//! with `lidt`. Keeps the table immutable after population except for explicit
//! gate openings during bring-up.

const std = @import("std");

/// Gate types for IDT descriptors (task, interrupt, trap).
pub const GateType = enum(u4) {
    task_gate = 0x5,
    interrupt_gate = 0xE,
    trap_gate = 0xF,
};

/// Descriptor privilege level (DPL) encodings used by gates.
pub const PrivilegeLevel = enum(u2) {
    ring_0 = 0x0,
    ring_3 = 0x3,
};

/// Raw IDT entry layout (16 bytes).
///
/// Fields split the ISR pointer into low/mid/high portions as required by
/// the hardware format. `ist` selects an optional Interrupt Stack Table slot.
const IDTEntry = packed struct {
    /// ISR address bits 0..15.
    isr_base_low: u16,
    /// Code segment selector for the ISR (e.g., kernel code).
    code_segment: u16,
    /// Interrupt Stack Table index (0 = disabled).
    ist: u3 = 0,
    _reserved0: u5 = 0,
    /// Gate type: interrupt or trap (task gates unsupported in long mode).
    gate_type: GateType,
    /// Storage segment bit (must be 0 for interrupt/trap gates).
    storage_segment: u1,
    /// Descriptor privilege level (who may invoke via `int`).
    privilege: PrivilegeLevel,
    /// Present bit.
    present: bool,
    /// ISR address bits 16..31.
    isr_base_mid: u16,
    /// ISR address bits 32..63.
    isr_base_high: u32,
    _reserved1: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(IDTEntry) == 16);
}

/// IDTR pointer used by `lidt`.
const IDTPtr = packed struct {
    /// Size of IDT in bytes minus 1.
    limit: u16,
    /// Linear base address of the IDT.
    base: u64,
};

/// Naked interrupt handler entry point type.
pub const interruptHandler = *const fn () callconv(.naked) void;

/// Total number of IDT entries (architectural maximum).
const NUM_IDT_ENTRIES = 256;

/// Computed `IDTR.limit` value.
const TABLE_SIZE: u16 = @sizeOf(IDTEntry) * NUM_IDT_ENTRIES - 1;

/// Global IDT initialized to non-present interrupt gates.
var idt: [NUM_IDT_ENTRIES]IDTEntry = [_]IDTEntry{.{
    .isr_base_low = 0,
    .code_segment = 0,
    .gate_type = .interrupt_gate,
    .storage_segment = 0,
    .privilege = .ring_0,
    .present = false,
    .isr_base_mid = 0,
    .isr_base_high = 0,
}} ** NUM_IDT_ENTRIES;

/// Current IDTR contents used by `lidt`.
var idt_ptr: IDTPtr = .{
    .limit = TABLE_SIZE,
    .base = 0,
};

/// Loads the IDT register with the global table.
pub fn init() void {
    idt_ptr.base = @intFromPtr(&idt);
    lidt(&idt_ptr);
}

/// Opens a gate at `int_num` pointing to `handler`.
///
/// Arguments:
/// - `int_num`: interrupt vector to configure (0..255)
/// - `handler`: naked ISR entry (must preserve calling convention expectations)
/// - `code_segment`: selector used for the ISR (e.g., kernel code selector)
/// - `privilege`: DPL permitting user or kernel `int` invocation
/// - `gate_type`: `.interrupt_gate` (clears IF) or `.trap_gate` (keeps IF)
pub fn openInterruptGate(
    int_num: u8,
    handler: interruptHandler,
    code_segment: u16,
    privilege: PrivilegeLevel,
    gate_type: GateType,
) void {
    std.debug.assert(int_num < NUM_IDT_ENTRIES);
    std.debug.assert(idt[int_num].present == false);

    const addr = @intFromPtr(handler);

    idt[int_num] = .{
        .isr_base_low = @truncate(addr),
        .code_segment = code_segment,
        .gate_type = gate_type,
        .storage_segment = 0,
        .privilege = privilege,
        .present = true,
        .isr_base_mid = @truncate(addr >> 16),
        .isr_base_high = @truncate(addr >> 32),
    };
}

/// Loads IDTR from `ptr`.
///
/// Arguments:
/// - `ptr`: pointer to `IDTPtr` structure to load.
fn lidt(ptr: *const IDTPtr) void {
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (ptr)
        : .{ .memory = true });
}
