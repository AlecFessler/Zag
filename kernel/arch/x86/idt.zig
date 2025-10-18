const std = @import("std");

pub const GateType = enum(u4) {
    task_gate = 0x5,
    interrupt_gate = 0xE,
    trap_gate = 0xF,
};

pub const PrivilegeLevel = enum(u2) {
    ring_0 = 0x0,
    ring_3 = 0x3,
};

const IDTEntry = packed struct {
    isr_base_low: u16,
    code_segment: u16,
    ist: u3 = 0,
    _reserved0: u5 = 0,
    gate_type: GateType,
    storage_segment: u1,
    privilege: PrivilegeLevel,
    present: bool,
    isr_base_mid: u16,
    isr_base_high: u32,
    _reserved1: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(IDTEntry) == 16);
}

const IDTPtr = packed struct {
    limit: u16,
    base: u64,
};

pub const interruptHandler = *const fn () callconv(.naked) void;


const NUM_IDT_ENTRIES = 256;
const TABLE_SIZE: u16 = @sizeOf(IDTEntry) * NUM_IDT_ENTRIES - 1;

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

var idt_ptr: IDTPtr = .{
    .limit = TABLE_SIZE,
    .base = 0,
};

pub fn init() void {
    idt_ptr.base = @intFromPtr(&idt);
    lidt(&idt_ptr);
}

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

fn lidt(ptr: *const IDTPtr) void {
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (ptr)
        : .{ .memory = true });
}
