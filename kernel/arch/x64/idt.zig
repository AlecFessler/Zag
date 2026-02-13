const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;

const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;

pub const GateType = enum(u4) {
    task_gate = 0x5,
    interrupt_gate = 0xE,
    trap_gate = 0xF,
};

const IDTEntry = packed struct(u128) {
    isr_base_low: u16,
    code_segment: u16,
    ist: u3 = 0,
    _res0: u5 = 0,
    gate_type: GateType,
    storage_segment: u1,
    privilege: PrivilegeLevel,
    present: bool,
    isr_base_mid: u16,
    isr_base_high: u32,
    _res1: u32 = 0,
};

const IDTPtr = packed struct {
    limit: u16,
    base: u64,
};

pub const interruptHandler = *const fn () callconv(.naked) void;

const NUM_IDT_ENTRIES: u64 = 256;
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

pub var idt_ptr: IDTPtr = .{
    .limit = TABLE_SIZE,
    .base = 0,
};

pub fn init() void {
    idt_ptr.base = @intFromPtr(&idt);
    cpu.lidt(&idt_ptr);
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
