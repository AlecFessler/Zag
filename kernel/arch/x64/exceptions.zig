const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const gdt = zag.arch.x64.gdt;

const GateType = zag.arch.x64.idt.GateType;
const PrivilegeLevel = zag.arch.x64.idt.PrivilegeLevel;

pub const Exception = enum(u5) {
    divide_by_zero = 0,
    single_step_debug = 1,
    non_maskable_interrupt = 2,
    breakpoint_debug = 3,
    overflow = 4,
    bound_range_exceeded = 5,
    invalid_opcode = 6,
    device_not_available = 7,
    double_fault = 8,
    coprocessor_segment_overrun = 9,
    invalid_task_state_segment = 10,
    segment_not_pressent = 11,
    stack_segment_fault = 12,
    general_protection_fault = 13,
    page_fault = 14,
    x87_floating_point = 16,
    alignment_check = 17,
    machine_check = 18,
    simd_floating_point = 19,
    virtualization = 20,
    security = 30,
};

const PFErrCode = struct {
    present: bool,
    is_write: bool,
    from_user: bool,
    rsvd_violation: bool,
    instr_fetch: bool,
    pkey: bool,
    cet_shadow_stack: bool,
    sgx: bool,

    pub fn from(err: u64) PFErrCode {
        return .{
            .present = (err & 0x1) != 0,
            .is_write = (err >> 1) & 1 == 1,
            .from_user = (err >> 2) & 1 == 1,
            .rsvd_violation = (err >> 3) & 1 == 1,
            .instr_fetch = (err >> 4) & 1 == 1,
            .pkey = (err >> 5) & 1 == 1,
            .cet_shadow_stack = (err >> 6) & 1 == 1,
            .sgx = (err >> 15) & 1 == 1,
        };
    }
};

pub const NUM_ISR_ENTRIES = 32;

pub fn init() void {
    for (0..NUM_ISR_ENTRIES) |i| {
        const privilege = switch (i) {
            @intFromEnum(Exception.breakpoint_debug),
            @intFromEnum(Exception.single_step_debug),
            => PrivilegeLevel.ring_3,
            else => PrivilegeLevel.ring_0,
        };
        idt.openInterruptGate(
            @intCast(i),
            interrupts.STUBS[i],
            gdt.KERNEL_CODE_OFFSET,
            privilege,
            GateType.interrupt_gate,
        );
    }
}
