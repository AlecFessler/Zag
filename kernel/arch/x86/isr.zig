const std = @import("std");

const idt = @import("idt.zig");
const interrupts = @import("interrupts.zig");

pub const NUM_ISR_ENTRIES = 32;
pub const SYSCALL_INT_VECTOR = 0x80;

/// Table to map whether a given ISR is expected to return
/// an error or not, so that a 0 error code can be pushed to
/// the stack for those that do not, allowing for a single
/// handler to route all interrupts through
const PUSHES_ERR = [_]bool{
    false, false, false, false, false, false, false, false,
    true,  false, true,  true,  true,  true,  false, false,
    false, true,  false, false, false, true,  false, false,
    false, false, false, false, false, false, true,  false,
};

pub const EXCEPTION_STRS: [NUM_ISR_ENTRIES][]const u8 = .{
    "Divide by Zero",
    "Single Step (Debugger)",
    "Non-Maskable Interrupt",
    "Breakpoint (Debugger)",
    "Overflow",
    "Bound Range Exceeded",
    "Invalid Opcode",
    "Device Not Available",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Invalid Task State Segment (TSS)",
    "Segment Not Present",
    "General Protection Fault",
    "Page Fault",
    "Reserved",
    "x87 FPU Floating Point Error",
    "Alignment Check",
    "Machine Check",
    "SIMD Floating Point",
    "Virtualization",
    "Control Protection",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Hypervisor Injection",
    "VMM Communication",
    "Security",
    "Reserved",
    "Triple Fault",
};

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

const ISR_STUBS: [NUM_ISR_ENTRIES]idt.interruptHandler = blk: {
    var arr: [NUM_ISR_ENTRIES]idt.interruptHandler = undefined;
    for (0..NUM_ISR_ENTRIES) |i| {
        arr[i] = interrupts.getInterruptStub(
            @intCast(i),
            PUSHES_ERR[i],
        );
    }
    break :blk arr;
};

const SYSCALL_STUB: idt.interruptHandler = interrupts.getInterruptStub(
    SYSCALL_INT_VECTOR,
    false,
);

const IsrHandler = *const fn (*interrupts.InterruptContext) void;

var isr_handlers: [NUM_ISR_ENTRIES]?IsrHandler = .{null} ** NUM_ISR_ENTRIES;
var syscall_handler: ?IsrHandler = null;

pub fn dispatchIsr(ctx: *interrupts.InterruptContext) void {
    std.debug.assert(ctx.int_num < NUM_ISR_ENTRIES or ctx.int_num == SYSCALL_INT_VECTOR);

    if (ctx.int_num == SYSCALL_INT_VECTOR) {
        if (syscall_handler) |handler| {
            handler(ctx);
        } else {
            @panic("Syscall handler not registered!\n");
        }
    } else {
        if (isr_handlers[ctx.int_num]) |handler| {
            handler(ctx);
        } else {
            @panic("ISR Vector gate not open!\n");
        }
    }
}

pub fn registerIsr(isr_num: u8, handler: IsrHandler) void {
    if (isr_num == SYSCALL_INT_VECTOR) {
        if (syscall_handler) |_| {
            @panic("Sycall handler already registered!\n");
        } else {
            syscall_handler = handler;
        }
    } else {
        if (isr_handlers[isr_num]) |_| {
            @panic("ISR handler already registered!\n");
        } else {
            isr_handlers[isr_num] = handler;
        }
    }
}

fn divByZeroHandler(ctx: *interrupts.InterruptContext) void {
    const cpl: u64 = ctx.cs & 3;
    if (cpl == 0) {
        @panic("Divide by zero in kernelspace!");
    } else {
        @panic("Divide by zero in userspace!");
    }
}

fn pageFaultHandler(ctx: *interrupts.InterruptContext) void {
    const cpl: u64 = ctx.cs & 3;
    if (cpl == 0) {
        @panic("Page fault in kernelspace!");
    } else {
        @panic("Page fault in userspace!");
    }
}

pub fn init() void {
    for (0..NUM_ISR_ENTRIES) |i| {
        const privilege = switch (i) {
            @intFromEnum(Exception.breakpoint_debug),
            @intFromEnum(Exception.single_step_debug),
            => idt.PrivilegeLevel.ring_3,
            else => idt.PrivilegeLevel.ring_0,
        };
        idt.openInterruptGate(
            @intCast(i),
            ISR_STUBS[i],
            0x08,
            privilege,
            idt.GateType.interrupt_gate,
        );
    }

    idt.openInterruptGate(
        SYSCALL_INT_VECTOR,
        SYSCALL_STUB,
        0x08,
        idt.PrivilegeLevel.ring_3,
        idt.GateType.interrupt_gate,
    );

    registerIsr(
        @intFromEnum(Exception.divide_by_zero),
        divByZeroHandler,
    );

    registerIsr(
        @intFromEnum(Exception.page_fault),
        pageFaultHandler,
    );
}
