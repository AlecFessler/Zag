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

/// Intel SDM Vol 3A, Table 7-1 — Protected-Mode Exceptions and Interrupts.
/// Vector assignments for architecturally defined exceptions (0-31).
/// Vector 15 is reserved; vectors 21-29 are reserved; vector 31 is reserved.
pub const Exception = enum(u5) {
    divide_by_zero = 0, // #DE — Fault, no error code
    single_step_debug = 1, // #DB — Fault/Trap, no error code
    non_maskable_interrupt = 2, // NMI — Interrupt, no error code
    breakpoint_debug = 3, // #BP — Trap, no error code
    overflow = 4, // #OF — Trap, no error code
    bound_range_exceeded = 5, // #BR — Fault, no error code
    invalid_opcode = 6, // #UD — Fault, no error code
    device_not_available = 7, // #NM — Fault, no error code
    double_fault = 8, // #DF — Abort, error code (zero)
    coprocessor_segment_overrun = 9, // reserved (Fault, no error code)
    invalid_task_state_segment = 10, // #TS — Fault, error code
    segment_not_present = 11, // #NP — Fault, error code
    stack_segment_fault = 12, // #SS — Fault, error code
    general_protection_fault = 13, // #GP — Fault, error code
    page_fault = 14, // #PF — Fault, error code (see PFErrCode)
    x87_floating_point = 16, // #MF — Fault, no error code
    alignment_check = 17, // #AC — Fault, error code (zero)
    machine_check = 18, // #MC — Abort, no error code
    simd_floating_point = 19, // #XM — Fault, no error code
    virtualization = 20, // #VE — Fault, no error code
    security = 30, // #SX — Fault, error code
};

/// Intel SDM Vol 3A §5.7, Figure 5-12 — Page-Fault Error Code.
/// Bit 0 (P): 0 = non-present page, 1 = protection violation.
/// Bit 1 (W/R): 0 = read access, 1 = write access.
/// Bit 2 (U/S): 0 = supervisor-mode access, 1 = user-mode access.
/// Bit 3 (RSVD): 1 = reserved bit set in paging-structure entry.
/// Bit 4 (I/D): 1 = instruction fetch (requires NXE=1 or SMEP=1).
/// Bit 5 (PK): 1 = protection-key violation.
/// Bit 6 (SS): 1 = shadow-stack access.
/// Bit 15 (SGX): 1 = SGX-specific access-control violation.
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

/// Intel SDM Vol 3A §7.2 — Vectors 0-31 are reserved for exceptions
/// and NMI; vectors 32-255 are available for external interrupts.
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
            interrupts.stubs[i],
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
        @intFromEnum(Exception.segment_not_present),
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
        .invalid_task_state_segment, .segment_not_present => .protection_fault,
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

/// Intel SDM Vol 3A §5.7 — #PF handler. CR2 holds the faulting linear
/// address; the error code on the stack encodes the fault reason per
/// Figure 5-12.
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
