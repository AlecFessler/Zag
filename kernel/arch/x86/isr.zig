//! CPU exception ISRs, syscall vector, and page-fault handling.
//!
//! Installs CPU exception gates (0..31), exposes a syscall vector (0x80),
//! registers a couple of default handlers, and routes all entries through the
//! common naked stub. Includes a minimal kernel page-fault handler that
//! demand-maps a fresh page for valid kernel VAddrs.

const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const interrupts = @import("interrupts.zig");
const memory = @import("memory");
const paging = @import("paging.zig");
const std = @import("std");
const vga = @import("vga.zig");

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

/// ISR handler function pointer signature.
const IsrHandler = *const fn (*interrupts.InterruptContext) void;

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

/// Human-readable names aligned to `NUM_ISR_ENTRIES`.
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

/// Count of CPU exception vectors we install (0..31).
pub const NUM_ISR_ENTRIES = 32;

/// Syscall interrupt vector (user-invocable).
pub const SYSCALL_INT_VECTOR = 0x80;

/// Table marking which exceptions push an error code (true) versus not (false).
///
/// Used to generate per-vector stubs that synthesize a 0 error code when the
/// CPU does not push one, so the dispatcher can use a single stack layout.
const PUSHES_ERR = [_]bool{
    //  0: #DE Divide Error
    false,
    //  1: #DB Debug Exception
    false,
    //  2: NMI Interrupt
    false,
    //  3: #BP Breakpoint
    false,
    //  4: #OF Overflow
    false,
    //  5: #BR BOUND Range Exceeded
    false,
    //  6: #UD Invalid Opcode
    false,
    //  7: #NM Device Not Available
    false,

    //  8: #DF Double Fault
    true,
    //  9: Coprocessor Segment Overrun
    false,
    // 10: #TS Invalid TSS
    true,
    // 11: #NP Segment Not Present
    true,
    // 12: #SS Stack Segment Fault
    true,
    // 13: #GP General Protection Fault
    true,
    // 14: #PF Page Fault
    true,
    // 15: #MF x87 FPU Floating-Point Error
    false,

    // 16: #AC Alignment Check
    true,
    // 17: #MC Machine Check
    false,
    // 18: #XM SIMD Floating-Point Exception
    false,
    // 19: #VE Virtualization Exception
    false,
    // 20: #CP Control Protection
    true,
    // 21: Reserved
    false,
    // 22: Reserved
    false,
    // 23: Reserved
    false,

    // 24: Reserved
    false,
    // 25: Reserved
    false,
    // 26: Reserved
    false,
    // 27: Reserved
    false,
    // 28: Reserved
    false,
    // 29: Reserved
    false,
    // 30: #SX Security Exception
    true,
    // 31: Reserved (Triple Fault)
    false,
};

/// Per-vector ISR stubs (0..31) generated to match `InterruptContext`.
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

/// Syscall stub used by vector `SYSCALL_INT_VECTOR`.
const SYSCALL_STUB: idt.interruptHandler = interrupts.getInterruptStub(
    SYSCALL_INT_VECTOR,
    false,
);

/// Optional handlers for exception vectors (null = unregistered).
var isr_handlers: [NUM_ISR_ENTRIES]?IsrHandler = .{null} ** NUM_ISR_ENTRIES;

/// Optional syscall handler.
var syscall_handler: ?IsrHandler = null;

/// Routes an ISR or syscall to a registered handler, or panics if missing.
///
/// Arguments:
/// - `ctx`: pointer to the interrupt context from the common stub.
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

/// Registers an ISR or syscall handler.
///
/// Panics if already registered.
/// - For `SYSCALL_INT_VECTOR`, sets `syscall_handler`.
/// - Otherwise fills `isr_handlers[isr_num]`.
///
/// Arguments:
/// - `isr_num`: exception vector (0..31) or `SYSCALL_INT_VECTOR`
/// - `handler`: function pointer to invoke on dispatch
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

/// Default handler: distinguishes kernel/user divide-by-zero and panics.
///
/// Arguments:
/// - `ctx`: interrupt context from the common stub
fn divByZeroHandler(ctx: *interrupts.InterruptContext) void {
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
fn pageFaultHandler(ctx: *interrupts.InterruptContext) void {
    if (pmm_mod.global_pmm == null) {
        @panic("Page fault prior to pmm initialization!");
    }
    const pf_err = PFErrCode.from(ctx.err_code);

    if (pf_err.rsvd_violation) @panic("Page tables have reserved bits set (RSVD).");
    if (pf_err.instr_fetch) @panic("Execute fault (NX) at kernel address.");

    const code_privilege_level: u64 = ctx.cs & 3;
    const faulting_vaddr = cpu.read_cr2();
    const faulting_page_vaddr = VAddr.fromInt(std.mem.alignBackward(
        u64,
        faulting_vaddr.addr,
        @intFromEnum(paging.PageSize.Page4K),
    ));

    if (code_privilege_level == 0) {
        if (pf_err.present) {
            @panic("Invalid memory access in kernelspace!");
        }
        if (vmm_mod.global_vmm == null) {
            @panic("Page fault prior to vmm initialization");
        }
        if (!vmm_mod.global_vmm.?.isValidVaddr(faulting_page_vaddr)) {
            vga.print("Invalid faulting vaddr: {X}\n", .{faulting_vaddr.addr});
            @panic("Invalid faulting address in kernel");
        }

        const pmm_iface = pmm_mod.global_pmm.?.allocator();
        const page = pmm_iface.alloc(paging.PageMem(.Page4K), 1) catch @panic("PMM OOM!");
        const phys_page_vaddr = VAddr.fromInt(@intFromPtr(page.ptr));
        const phys_page_paddr = PAddr.fromVAddr(phys_page_vaddr, .physmap);

        const pml4_paddr = PAddr.fromInt(paging.read_cr3().addr & ~@as(u64, 0xfff));
        const pml4_vaddr = VAddr.fromPAddr(pml4_paddr, .physmap);

        paging.mapPage(
            @ptrFromInt(pml4_vaddr.addr),
            phys_page_paddr,
            faulting_page_vaddr,
            .ReadWrite,
            true,
            .Supervisor,
            .Page4K,
            .physmap,
            pmm_iface,
        );

        cpu.invlpg(faulting_page_vaddr);
    } else {
        @panic("Userspace page fault handler not implemented!");
    }
}
