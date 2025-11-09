//! CPU exception ISRs, syscall vector, and page-fault handling.
//!
//! Installs CPU exception gates (0..31), exposes a syscall vector (0x80),
//! registers default handlers, and routes all entries through the common naked
//! stub. Includes a kernel/userspace page-fault handler that demand-maps a
//! fresh 4 KiB page for valid virtual addresses (kernel or user) on non-present
//! faults; present faults are treated as protection errors and panic.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `Exception` – architectural exception vectors (subset explicitly listed).
//! - `PFErrCode` – parsed x86-64 page-fault error code with convenience flags.
//!
//! ## Constants
//! - `NUM_ISR_ENTRIES` – number of exception gates (0..31) to install.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `init` – install exception gates and register default handlers + syscall gate.
//! - `breakpointHandler` – #BP handler (returns in kernelspace; panics in userspace).
//! - `debugHandler` – #DB handler (returns in kernelspace; panics in userspace).
//! - `divByZeroHandler` – #DE handler (panics; message varies by CPL).
//! - `doubleFaultHandler` – #DF handler (panics; message varies by CPL).
//! - `pageFaultHandler` – #PF handler; demand-maps non-present pages, panics on protection faults.

const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const interrupts = @import("interrupts.zig");
const paging = @import("paging.zig");
const serial = @import("serial.zig");
const std = @import("std");
const zag = @import("zag");

const memory = zag.memory;
const pmm_mod = memory.PhysicalMemoryManager;
const sched = zag.sched.scheduler;
const debugger = zag.debugger;

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
    present: bool, // bit 0
    is_write: bool, // bit 1
    from_user: bool, // bit 2
    rsvd_violation: bool, // bit 3
    instr_fetch: bool, // bit 4
    pkey: bool, // bit 5
    cet_shadow_stack: bool, // bit 6
    sgx: bool, // bit 15

    /// Summary:
    /// Converts a raw page-fault error code into a parsed `PFErrCode`.
    ///
    /// Arguments:
    /// - `err`: Raw error code from the page-fault (#PF) exception.
    ///
    /// Returns:
    /// - `PFErrCode` populated with decoded flag fields.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
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

const PAddr = paging.PAddr;
const PhysicalMemoryManager = pmm_mod.PhysicalMemoryManager;
const VAddr = paging.VAddr;

pub const NUM_ISR_ENTRIES = 32;

/// Summary:
/// Installs IDT gates for exception vectors and the syscall vector, and
/// registers default handlers for divide-by-zero and page-fault.
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
            interrupts.STUBS[i],
            0x08,
            privilege,
            idt.GateType.interrupt_gate,
        );
    }

    interrupts.registerException(
        @intFromEnum(Exception.divide_by_zero),
        divByZeroHandler,
    );
    interrupts.registerException(
        @intFromEnum(Exception.single_step_debug),
        debugHandler,
    );
    interrupts.registerException(
        @intFromEnum(Exception.breakpoint_debug),
        breakpointHandler,
    );
    interrupts.registerException(
        @intFromEnum(Exception.double_fault),
        doubleFaultHandler,
    );
    interrupts.registerException(
        @intFromEnum(Exception.page_fault),
        pageFaultHandler,
    );

    const syscall_int_vec = @intFromEnum(idt.IntVectors.syscall);
    idt.openInterruptGate(
        @intCast(syscall_int_vec),
        interrupts.STUBS[syscall_int_vec],
        0x08,
        idt.PrivilegeLevel.ring_3,
        idt.GateType.interrupt_gate,
    );
    // When the syscall handler exists, register it via:
    // interrupts.registerSoftware(syscall_int_vec, syscallHandler,);
}

/// Summary:
/// #BP breakpoint handler. Dumps the frame, returns in kernelspace, panics in userspace.
///
/// Arguments:
/// - `ctx`: Interrupt context captured by the common stub.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics when invoked from userspace.
fn breakpointHandler(ctx: *cpu.Context) void {
    debugger.dumpInterruptFrame(ctx);
    const cpl: u64 = ctx.cs & 3;
    if (cpl == 0) {
        return;
    } else {
        @panic("Divide by zero in userspace!");
    }
}

/// Summary:
/// #DB single-step/trace handler. Dumps the frame, returns in kernelspace, panics in userspace.
///
/// Arguments:
/// - `ctx`: Interrupt context captured by the common stub.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics when invoked from userspace.
fn debugHandler(ctx: *cpu.Context) void {
    debugger.dumpInterruptFrame(ctx);
    const cpl: u64 = ctx.cs & 3;
    if (cpl == 0) {
        return;
    } else {
        @panic("Divide by zero in userspace!");
    }
}

/// Summary:
/// #DE divide-by-zero handler. Dumps the frame and panics; message varies by CPL.
///
/// Arguments:
/// - `ctx`: Interrupt context captured by the common stub.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Always panics on divide-by-zero.
fn divByZeroHandler(ctx: *cpu.Context) void {
    debugger.dumpInterruptFrame(ctx);
    const cpl: u64 = ctx.cs & 3;
    if (cpl == 0) {
        @panic("Divide by zero in kernelspace!");
    } else {
        @panic("Divide by zero in userspace!");
    }
}

/// Summary:
/// #DF double-fault handler. Dumps the frame and panics; message varies by CPL.
///
/// Arguments:
/// - `ctx`: Interrupt context captured by the common stub.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Always panics on double fault.
fn doubleFaultHandler(ctx: *cpu.Context) void {
    debugger.dumpInterruptFrame(ctx);
    const cpl: u64 = ctx.cs & 3;
    if (cpl == 0) {
        @panic("Double fault in kernelspace!");
    } else {
        @panic("Double fault in userspace!");
    }
}

/// Summary:
/// Kernel page-fault handler that demand-maps a 4 KiB page on non-present faults
/// for addresses valid in either the kernel or the current process address space.
/// Present faults are treated as protection errors and panic.
///
/// Arguments:
/// - `ctx`: Interrupt context captured by the common stub.
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics on RSVD violations, PMM/VMM uninitialized, execute faults in kernel,
///   protection faults, invalid address (neither kspace nor current uspace), or
///   userspace invalid-access conditions.
fn pageFaultHandler(ctx: *cpu.Context) void {
    const pf_err = PFErrCode.from(ctx.err_code);
    if (pf_err.rsvd_violation) {
        @panic("Page tables have reserved bits set (RSVD).");
    }
    if (pmm_mod.global_pmm == null) {
        @panic("Page fault prior to pmm initialization!");
    }

    const pmm_iface = pmm_mod.global_pmm.?.allocator();

    const faulting_virt = cpu.read_cr2();
    const faulting_page_virt = VAddr.fromInt(std.mem.alignBackward(
        u64,
        faulting_virt.addr,
        @intFromEnum(paging.PageSize.Page4K),
    ));

    const ring_0 = @intFromEnum(idt.PrivilegeLevel.ring_0);
    const ring_3 = @intFromEnum(idt.PrivilegeLevel.ring_3);
    const cpl: u64 = ctx.cs & ring_3;

    if (pf_err.present) {
        serial.print("Faulting Instruction: {X}\nFaulting Address: {X}\nFaulting Page: {X}\nPresent: {}\nIs Write: {}\nIs fetch: {}\n", .{
            ctx.rip,
            faulting_virt.addr,
            faulting_page_virt.addr,
            pf_err.present,
            pf_err.is_write,
            pf_err.instr_fetch,
        });
        paging.dumpPageWalk(faulting_page_virt);
        if (cpl == ring_0) {
            @panic("Kernel page fault: invalid access");
        } else {
            @panic("User page fault: invalid access (process killing not implemented yet)");
        }
    }

    const page = pmm_iface.create(paging.PageMem(.Page4K)) catch @panic("PMM OOM!");
    const phys_page_virt = VAddr.fromInt(@intFromPtr(page));
    const phys_page_phys = PAddr.fromVAddr(phys_page_virt, .physmap);

    const pml4_virt = paging.currentPml4VAddr();

    const in_kspace = sched.kproc.vmm.isValidVAddr(faulting_virt);
    const in_uspace = blk: {
        if (sched.running_thread) |rt| {
            break :blk rt.proc.vmm.isValidVAddr(faulting_virt);
        } else break :blk false;
    };
    const permissions: paging.User = blk: {
        if (in_kspace) {
            break :blk .su;
        } else if (in_uspace) {
            break :blk .u;
        } else {
            debugger.dumpInterruptFrame(ctx);
            @panic("Non-present page in neither kernel or user address space!");
        }
    };

    paging.mapPage(
        @ptrFromInt(pml4_virt.addr),
        phys_page_phys,
        faulting_page_virt,
        .rw,
        .nx,
        .cache,
        permissions,
        .Page4K,
        .physmap,
        pmm_iface,
    );
    cpu.invlpg(faulting_page_virt);
}
