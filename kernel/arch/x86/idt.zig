//! IDT setup and interrupt gate utilities for x86-64.
//!
//! Provides IDT entry formats and helpers to open gates and load the IDT with
//! `lidt`. The global table is initialized non-present and treated as immutable
//! after population, except for explicit gate openings during bring-up.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `GateType` – architectural gate kind encodings (task/interrupt/trap).
//! - `IntVectors` – project-specific interrupt vector assignments.
//! - `PrivilegeLevel` – descriptor privilege level encodings (rings).
//! - `IDTEntry` – raw 16-byte IDT descriptor layout.
//! - `IDTPtr` – IDTR operand used by `lidt`.
//! - `interruptHandler` – naked ISR entrypoint function pointer type.
//!
//! ## Constants
//! - `NUM_IDT_ENTRIES` – architectural IDT entry count (256).
//! - `TABLE_SIZE` – value for `IDTR.limit` (bytes-1 for the table).
//!
//! ## Variables
//! - `idt` – global IDT table, initially all non-present interrupt gates.
//! - `idt_ptr` – IDTR image used when calling `lidt`.
//!
//! ## Functions
//! - `init` – compute IDTR base and load the IDT.
//! - `openInterruptGate` – populate a specific vector with a handler/gate.
//! - `lidt` – private helper to execute the `lidt` instruction.

const std = @import("std");

/// Gate types for IDT descriptors (task, interrupt, trap).
pub const GateType = enum(u4) {
    task_gate = 0x5,
    interrupt_gate = 0xE,
    trap_gate = 0xF,
};

/// Project-specific interrupt vectors (syscall, scheduler tick, spurious).
pub const IntVectors = enum(u8) {
    syscall = 0x80,
    sched = 0xFE,
    spurious = 0xFF,
};

/// Descriptor privilege level encodings (ring 0 and ring 3).
pub const PrivilegeLevel = enum(u2) {
    ring_0 = 0x0,
    ring_3 = 0x3,
};

/// Raw IDT entry layout (16 bytes), matching x86-64 hardware format.
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

/// IDTR pointer used by `lidt` to install the IDT.
const IDTPtr = packed struct {
    /// Size of IDT in bytes minus 1.
    limit: u16,
    /// Linear base address of the IDT.
    base: u64,
};

/// Naked interrupt handler entry point function pointer type.
pub const interruptHandler = *const fn () callconv(.naked) void;

/// Total number of IDT entries (architectural maximum, 256).
const NUM_IDT_ENTRIES: usize = 256;

/// Precomputed `IDTR.limit` value for a full table.
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

/// Summary:
/// Loads the IDT by pointing `idtr.base` at the global table and executing `lidt`.
///
/// Arguments:
/// - None.
///
/// Returns:
/// - void.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn init() void {
    idt_ptr.base = @intFromPtr(&idt);
    lidt(&idt_ptr);
}

/// Summary:
/// Opens a gate at `int_num` pointing to `handler`, using the given selector,
/// privilege level, and gate type (interrupt or trap).
///
/// Arguments:
/// - `int_num`: Interrupt vector to configure (0..255).
/// - `handler`: Naked ISR entrypoint (must follow calling convention).
/// - `code_segment`: Code segment selector for the ISR (e.g., kernel CS).
/// - `privilege`: Descriptor privilege level that may invoke the gate.
/// - `gate_type`: `.interrupt_gate` (clears IF) or `.trap_gate` (leaves IF set).
///
/// Returns:
/// - void.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics in debug builds if `int_num >= 256` or if the gate is already present.
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

/// Summary:
/// Executes the `lidt` instruction to install the IDT from `ptr`.
///
/// Arguments:
/// - `ptr`: Pointer to an `IDTPtr` structure to load.
///
/// Returns:
/// - void.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
fn lidt(ptr: *const IDTPtr) void {
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (ptr)
        : .{ .memory = true });
}
