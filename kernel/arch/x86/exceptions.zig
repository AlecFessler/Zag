//! CPU exception ISRs, syscall vector, and page-fault handling.
//!
//! Installs CPU exception gates (0..31), exposes a syscall vector (0x80),
//! registers a couple of default handlers, and routes all entries through the
//! common naked stub. Includes a minimal kernel page-fault handler that
//! demand-maps a fresh page for valid kernel VAddrs.

const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const interrupts = @import("interrupts.zig");
const paging = @import("paging.zig");
const std = @import("std");
const zag = @import("zag");
const serial = @import("serial.zig");

const memory = zag.memory;
const pmm_mod = memory.PhysicalMemoryManager;
const vmm_mod = memory.VirtualMemoryManager;

const PAddr = paging.PAddr;
const PhysicalMemoryManager = pmm_mod.PhysicalMemoryManager;
const VAddr = paging.VAddr;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;

/// Architectural exception vectors (subset shown explicitly).
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

/// Page fault error code parser.
const PFErrCode = struct {
    present: bool, // bit 0
    is_write: bool, // bit 1
    from_user: bool, // bit 2
    rsvd_violation: bool, // bit 3
    instr_fetch: bool, // bit 4
    pkey: bool, // bit 5
    cet_shadow_stack: bool, // bit 6
    sgx: bool, // bit 15

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

/// Installs IDT gates for exception vectors and the syscall vector.
///
/// Also registers default handlers for divide-by-zero and page-fault.
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
    // will register syscall here with
    // interrupts.registerSoftware(syscall_int_vec, syscallHandler,);
    // when the handler exists
}

/// Default handler: distinguishes kernel/user divide-by-zero and panics.
///
/// Arguments:
/// - `ctx`: interrupt context from the common stub
fn divByZeroHandler(ctx: *cpu.Context) void {
    const cpl: u64 = ctx.cs & 3;
    if (cpl == 0) {
        @panic("Divide by zero in kernelspace!");
    } else {
        @panic("Divide by zero in userspace!");
    }
}

/// Kernel page-fault handler: demand-maps a 4KiB page for valid kernel VAddrs.
///
/// Steps:
/// - Reject faults before PMM/VMM init.
/// - Validate that the faulting address lies within a reserved kernel VMM
///   region; panic if not.
/// - Allocate a physical page from the PMM and map it RW at the faulting page.
/// - Invalidate the single TLB entry (`invlpg`).
///
/// Userspace faults are not implemented and will panic.
///
/// Arguments:
/// - `ctx`: interrupt context from the common stub
fn pageFaultHandler(ctx: *cpu.Context) void {
    const pf_err = PFErrCode.from(ctx.err_code);

    if (pf_err.rsvd_violation) @panic("Page tables have reserved bits set (RSVD).");
    if (pmm_mod.global_pmm == null) {
        @panic("Page fault prior to pmm initialization!");
    }

    const code_privilege_level: u64 = ctx.cs & 3;
    const faulting_virt = cpu.read_cr2();
    const faulting_page_virt = VAddr.fromInt(std.mem.alignBackward(
        u64,
        faulting_virt.addr,
        @intFromEnum(paging.PageSize.Page4K),
    ));

    serial.print("Faulting Instruction: {X}\nFaulting Address: {X}\nFaulting Page: {X}\nPresent: {}\nIs Write: {}\n", .{
        ctx.rip,
        faulting_virt.addr,
        faulting_page_virt.addr,
        pf_err.present,
        pf_err.is_write,
    });

    if (code_privilege_level == 0) {
        if (pf_err.instr_fetch) @panic("Execute fault (NX) at kernel address.");
        if (pf_err.present) {
            @panic("Invalid memory access in kernelspace!");
        }
        if (vmm_mod.global_vmm == null) {
            @panic("Page fault prior to vmm initialization");
        }
        if (!vmm_mod.global_vmm.?.isValidVaddr(faulting_page_virt)) {
            @panic("Invalid faulting address in kernel");
        }

        const pmm_iface = pmm_mod.global_pmm.?.allocator();
        const page = pmm_iface.alloc(paging.PageMem(.Page4K), 1) catch @panic("PMM OOM!");
        const phys_page_virt = VAddr.fromInt(@intFromPtr(page.ptr));
        const phys_page_phys = PAddr.fromVAddr(phys_page_virt, .physmap);

        const pml4_phys = PAddr.fromInt(paging.read_cr3().addr & ~@as(u64, 0xfff));
        const pml4_virt = VAddr.fromPAddr(pml4_phys, .physmap);

        paging.mapPage(
            @ptrFromInt(pml4_virt.addr),
            phys_page_phys,
            faulting_page_virt,
            .rw,
            .nx,
            .cache,
            .su,
            .Page4K,
            .physmap,
            pmm_iface,
        );

        cpu.invlpg(faulting_page_virt);
    } else {
        @panic("Userspace page fault handler not implemented!");
    }
}
