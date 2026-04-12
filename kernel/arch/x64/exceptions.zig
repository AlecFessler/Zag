const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const cpu = zag.arch.x64.cpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const scheduler = zag.sched.scheduler;

const FaultReason = zag.perms.permissions.FaultReason;
const GateType = zag.arch.x64.idt.GateType;
const PageFaultContext = zag.arch.dispatch.PageFaultContext;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const VAddr = zag.memory.address.VAddr;

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
    interrupts.registerVector(
        @intFromEnum(Exception.page_fault),
        pageFaultHandler,
        .exception,
    );

    const exception_vectors = [_]u5{
        @intFromEnum(Exception.divide_by_zero),
        @intFromEnum(Exception.single_step_debug),
        @intFromEnum(Exception.non_maskable_interrupt),
        @intFromEnum(Exception.breakpoint_debug),
        @intFromEnum(Exception.overflow),
        @intFromEnum(Exception.bound_range_exceeded),
        @intFromEnum(Exception.invalid_opcode),
        @intFromEnum(Exception.device_not_available),
        @intFromEnum(Exception.double_fault),
        @intFromEnum(Exception.coprocessor_segment_overrun),
        @intFromEnum(Exception.invalid_task_state_segment),
        @intFromEnum(Exception.segment_not_pressent),
        @intFromEnum(Exception.stack_segment_fault),
        @intFromEnum(Exception.general_protection_fault),
        // page_fault already registered above
        @intFromEnum(Exception.x87_floating_point),
        @intFromEnum(Exception.alignment_check),
        @intFromEnum(Exception.machine_check),
        @intFromEnum(Exception.simd_floating_point),
        @intFromEnum(Exception.virtualization),
        @intFromEnum(Exception.security),
    };

    for (exception_vectors) |vec| {
        interrupts.registerVector(vec, exceptionHandler, .exception);
    }
}

fn exceptionFaultReason(vector: u5) ?FaultReason {
    return switch (@as(Exception, @enumFromInt(vector))) {
        .divide_by_zero, .overflow, .bound_range_exceeded => .arithmetic_fault,
        .x87_floating_point, .simd_floating_point => .arithmetic_fault,
        .invalid_opcode, .device_not_available => .illegal_instruction,
        .alignment_check => .alignment_fault,
        .general_protection_fault, .stack_segment_fault => .protection_fault,
        .invalid_task_state_segment, .segment_not_pressent => .protection_fault,
        .virtualization, .security => .protection_fault,
        .single_step_debug => null,
        .breakpoint_debug => .breakpoint,
        .double_fault, .machine_check => null,
        .non_maskable_interrupt, .coprocessor_segment_overrun => null,
        .page_fault => unreachable,
    };
}

fn exceptionHandler(ctx: *cpu.Context) void {
    const vector: u5 = @intCast(ctx.int_num);
    const exception: Exception = @enumFromInt(vector);
    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);
    const from_user = (ctx.cs & ring_3) == ring_3;

    if (from_user) {
        // Debug/single-step from userspace: just resume.
        if (exception == .single_step_debug) return;

        if (exceptionFaultReason(vector)) |reason| {
            const thread = scheduler.currentThread() orelse
                @panic("user exception with no current thread");
            arch.print("K: EXCEPTION pid={d} vec={d} err=0x{x}\n", .{
                thread.process.pid, vector, ctx.err_code,
            });
            if (thread.process.faultBlock(thread, reason, ctx.rip, ctx.rip, ctx)) {
                arch.enableInterrupts();
                scheduler.yield();
                return;
            }
            thread.process.kill(reason);
            arch.enableInterrupts();
            while (true) arch.halt();
        }
    }

    switch (exception) {
        .double_fault => @panic("Double fault"),
        .machine_check => @panic("Machine check exception"),
        .non_maskable_interrupt => @panic("NMI"),
        .general_protection_fault => {
            arch.print("GPF at rip=0x{x} err=0x{x}\n", .{ ctx.rip, ctx.err_code });
            @panic("General protection fault");
        },
        .page_fault => unreachable,
        else => {
            arch.print("Exception {d} at rip=0x{x} err=0x{x}\n", .{
                vector, ctx.rip, ctx.err_code,
            });
            @panic("Unhandled kernel exception");
        },
    }
}

fn pageFaultHandler(ctx: *cpu.Context) void {
    const pf_err = PFErrCode.from(ctx.err_code);
    if (pf_err.rsvd_violation) {
        @panic("Page tables have reserved bits set (RSVD).");
    }
    const faulting_addr = cpu.readCr2();
    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);
    const from_user = (ctx.cs & ring_3) == ring_3;
    const pf_ctx = PageFaultContext{
        .faulting_address = faulting_addr,
        .is_kernel_privilege = !from_user,
        .is_write = pf_err.is_write,
        .is_exec = pf_err.instr_fetch,
        .rip = ctx.rip,
        .user_ctx = if (from_user) ctx else null,
    };
    zag.memory.fault.handlePageFault(&pf_ctx);
}
