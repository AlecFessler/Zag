const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const cpu = zag.arch.x64.cpu;
const exceptions = zag.arch.x64.exceptions;
const fpu = zag.sched.fpu;
const futex = zag.proc.futex;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const kprof_dump = zag.kprof.dump;
const paging_mod = zag.arch.x64.paging;
const sched = zag.sched.scheduler;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const GateType = zag.arch.x64.idt.GateType;
const PAddr = zag.memory.address.PAddr;
const Process = zag.proc.process.Process;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const SchedInterruptContext = zag.sched.scheduler.SchedInterruptContext;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const UserViewEntry = zag.perms.permissions.UserViewEntry;
const VAddr = zag.memory.address.VAddr;

/// 16 IRQ lines (vectors 32-47) — legacy ISA IRQs remapped above the 32 exception
/// vectors reserved by the architecture.
/// Intel SDM Vol 3A, §7.2 "Exception and Interrupt Vectors", Table 7-1 — vectors
/// 0-31 are reserved for exceptions; external device interrupts start at vector 32.
const num_irq_entries = 16;

var spurious_interrupts: u64 = 0;

/// Maps IRQ line numbers to the DeviceRegion that owns each line.
/// Populated during firmware table parsing. Static after boot.
/// Systems.md §24.
pub var irq_table: [256]?*DeviceRegion = [_]?*DeviceRegion{null} ** 256;

/// Per-IRQ-line owner info for the IRQ pending bit path.
/// Set by registerIrqOwner when a process takes ownership of a device IRQ.
pub const IrqOwner = struct {
    process: *Process,
    slot_index: u16,
};

pub var irq_owners: [256]?IrqOwner = [_]?IrqOwner{null} ** 256;

/// I/O APIC MMIO base virtual address. Set during ACPI parsing.
var ioapic_base: u64 = 0;
var ioapic_lock: SpinLock = .{};

/// Sets up IDT gates for hardware IRQs, the spurious interrupt vector, the TLB
/// shootdown IPI vector, and the scheduler timer vector.
pub fn init() void {
    const offset = exceptions.NUM_ISR_ENTRIES;
    for (offset..offset + num_irq_entries) |i| {
        idt.openInterruptGate(
            @intCast(i),
            interrupts.stubs[i],
            gdt.KERNEL_CODE_OFFSET,
            PrivilegeLevel.ring_0,
            GateType.interrupt_gate,
        );
    }

    // Intel SDM Vol 3A, §13.9 "Spurious Interrupt" — the spurious-interrupt vector
    // register (SVR) at FEE0_00F0H specifies the vector delivered when the APIC
    // generates a spurious interrupt. Default after reset is 0xFF. The handler must
    // NOT send an EOI (spurious delivery does not set ISR).
    const spurious_int_vec = @intFromEnum(interrupts.IntVecs.spurious);
    idt.openInterruptGate(
        @intCast(spurious_int_vec),
        interrupts.stubs[spurious_int_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        spurious_int_vec,
        spuriousHandler,
        .external,
    );

    const tlb_vec = @intFromEnum(interrupts.IntVecs.tlb_shootdown);
    idt.openInterruptGate(
        tlb_vec,
        interrupts.stubs[tlb_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        tlb_vec,
        paging_mod.tlbShootdownHandler,
        .external,
    );

    const kprof_vec = @intFromEnum(interrupts.IntVecs.kprof_dump);
    idt.openInterruptGate(
        kprof_vec,
        interrupts.stubs[kprof_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        kprof_vec,
        kprofDumpHandler,
        .external,
    );

    // Lazy-FPU cross-core flush IPI vector. Sent by `cpu.fpuFlushIpi`
    // when the scheduler migrates a thread whose FP regs still live on
    // a remote core's hardware. Receiver runs `fpuFlushIpiHandler` to
    // FXSAVE the requested thread's state from this core's regs into
    // the thread's `fpu_state` buffer, then acks the mailbox.
    const fpu_flush_vec = @intFromEnum(interrupts.IntVecs.fpu_flush);
    idt.openInterruptGate(
        fpu_flush_vec,
        interrupts.stubs[fpu_flush_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        fpu_flush_vec,
        fpuFlushIpiHandler,
        .external,
    );

    const sched_int_vec = @intFromEnum(interrupts.IntVecs.sched);
    idt.openInterruptGate(
        @intCast(sched_int_vec),
        interrupts.stubs[sched_int_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        sched_int_vec,
        schedTimerHandler,
        .external,
    );

    // Register device IRQ handlers for vectors 32-47 (ISA IRQ lines 0-15).
    // Intel SDM Vol 3A, §7.2 — vectors 32+ are available for external interrupts.
    for (offset..offset + num_irq_entries) |i| {
        interrupts.registerVector(
            @intCast(i),
            deviceIrqHandler,
            .external,
        );
    }

    // SYSCALL/SYSRET replaces the old INT 0x80 path. The SYSCALL entry
    // point is set via MSR_LSTAR in cpu.initSyscall(); no IDT gate needed.
    // Intel SDM Vol 3A, §8.5.4 "SYSCALL and SYSENTER" — SYSCALL transfers
    // control without the IDT, using IA32_LSTAR for the entry point RIP.
}

/// IRQ pending bit position within the user view entry's field0.
/// Bit 16 is used because the lower bits carry device_type/device_class
/// metadata; bit 16 is otherwise unused padding in the device entry layout.
const IRQ_PENDING_BIT: u64 = 1 << 16;

/// Device IRQ handler — called for vectors 32-47 (ISA IRQ lines 0-15).
/// Masks the IRQ line, sets bit 16 of field0 in the device's user view entry
/// to signal the pending IRQ, and wakes any futex waiters on that address.
fn deviceIrqHandler(ctx: *cpu.Context) void {
    // The vector number is embedded in the Context by the interrupt stub.
    // IRQ line = vector - 32 (ISA IRQ remapping).
    const vector: u8 = @truncate(ctx.int_num);
    const irq_line = vector - 32;

    // Mask the IRQ to prevent re-entry until userspace acknowledges.
    maskIrq(irq_line);

    // Look up the owner info for this IRQ line.
    const owner = irq_owners[irq_line] orelse return;
    setIrqPendingBitForOwner(owner);
}

/// Set bit 16 of field0 in the device's user view entry via atomic OR,
/// then wake any futex waiters on that physical address.
/// Called from the device IRQ handler (interrupts disabled).
fn setIrqPendingBitForOwner(owner: IrqOwner) void {
    const proc = owner.process;
    if (proc.perm_view_phys.addr == 0) return;

    // Calculate physical address of field0 in the user view entry.
    // Each UserViewEntry is 32 bytes; field0 is at offset 16.
    const field0_paddr = PAddr.fromInt(
        proc.perm_view_phys.addr + @as(u64, owner.slot_index) * @sizeOf(UserViewEntry) + @offsetOf(UserViewEntry, "field0"),
    );
    const field0_vaddr = VAddr.fromPAddr(field0_paddr, null);
    const field0_ptr: *u64 = @ptrFromInt(field0_vaddr.addr);

    // Atomic OR to set bit 16.
    _ = @atomicRmw(u64, field0_ptr, .Or, IRQ_PENDING_BIT, .release);

    // Wake all futex waiters on the physical address of field0.
    _ = futex.wake(field0_paddr, std.math.maxInt(u32));
}

/// Clear bit 16 of field0 in the device's user view entry via atomic AND.
/// Called from sysIrqAck after unmasking the IRQ line.
pub fn clearIrqPendingBit(irq_line: u8) void {
    const owner = irq_owners[irq_line] orelse return;
    const proc = owner.process;
    if (proc.perm_view_phys.addr == 0) return;

    const field0_paddr = PAddr.fromInt(
        proc.perm_view_phys.addr + @as(u64, owner.slot_index) * @sizeOf(UserViewEntry) + @offsetOf(UserViewEntry, "field0"),
    );
    const field0_vaddr = VAddr.fromPAddr(field0_paddr, null);
    const field0_ptr: *u64 = @ptrFromInt(field0_vaddr.addr);

    // Atomic AND to clear bit 16.
    _ = @atomicRmw(u64, field0_ptr, .And, ~IRQ_PENDING_BIT, .release);
}

/// Register the IRQ owner info for a device. Called when a process receives
/// a device handle with IRQ rights.
pub fn registerIrqOwner(irq_line: u8, proc: *Process, slot_index: u16) void {
    irq_owners[irq_line] = .{
        .process = proc,
        .slot_index = slot_index,
    };
}

/// Intel SDM Vol 3A, §13.9 — spurious interrupt handler must return without EOI
/// because the APIC does not set the ISR bit for spurious deliveries.
fn spuriousHandler(ctx: *cpu.Context) void {
    _ = ctx;
    spurious_interrupts += 1;
}

/// Kprof-dump IPI handler: park this CPU inside kprof.dump so the
/// dumping core can quiesce every other CPU before serial-dumping.
/// Never returns — parkForDump halts after dump_done is observed.
fn kprofDumpHandler(_: *cpu.Context) void {
    kprof_dump.parkForDump();
}

/// IPI handler for the lazy-FPU cross-core flush. Reads the requested
/// thread from this core's mailbox, calls into the generic FPU module
/// (which checks if this core is still the owner and FXSAVEs if so),
/// then acks the mailbox so the requester unblocks.
fn fpuFlushIpiHandler(_: *cpu.Context) void {
    const core_id: u8 = @truncate(arch.coreID());
    const slot = &interrupts.fpu_flush_mailbox[core_id];
    const opaque_ptr = @atomicLoad(?*anyopaque, &slot.requested_thread, .acquire) orelse {
        slot.ackDone();
        return;
    };
    const thread: *Thread = @ptrCast(@alignCast(opaque_ptr));
    fpu.flushIpiHandler(thread);
    slot.ackDone();
}

fn schedTimerHandler(ctx: *cpu.Context) void {
    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);
    const from_user = (ctx.cs & ring_3) == 3;

    var sched_interrupt_ctx: SchedInterruptContext = undefined;
    sched_interrupt_ctx.privilege = if (from_user) .user else .kernel;
    sched_interrupt_ctx.thread_ctx = @ptrCast(ctx);

    sched.schedTimerHandler(sched_interrupt_ctx);
}

/// Set the I/O APIC MMIO base address. Called during ACPI parsing.
pub fn setIoapicBase(phys_addr: u32) void {
    const phys = PAddr.fromInt(@as(u64, phys_addr));
    ioapic_base = VAddr.fromPAddr(phys, null).addr;
}

/// Mask an IRQ line by setting bit 16 (interrupt mask) of the low dword of
/// the I/O APIC redirection table entry for the given IRQ.
/// 82093AA I/O APIC Datasheet, §3.2.4 "I/O Redirection Table Registers" —
/// bit 16 of the low dword is the Interrupt Mask bit; 1 = masked.
/// Redirection table entry n occupies registers 0x10+2n (low) and 0x11+2n (high).
pub fn maskIrq(irq_line: u8) void {
    if (ioapic_base == 0) return;
    const reg = @as(u32, 0x10) + @as(u32, irq_line) * 2;
    const irq_state = ioapic_lock.lockIrqSave();
    const val = ioapicRead(reg);
    ioapicWrite(reg, val | (1 << 16));
    ioapic_lock.unlockIrqRestore(irq_state);
}

/// Unmask an IRQ line by clearing bit 16 (interrupt mask) of the low dword of
/// the I/O APIC redirection table entry for the given IRQ.
/// 82093AA I/O APIC Datasheet, §3.2.4 "I/O Redirection Table Registers" —
/// bit 16 of the low dword is the Interrupt Mask bit; 0 = unmasked.
pub fn unmaskIrq(irq_line: u8) void {
    if (ioapic_base == 0) return;
    const reg = @as(u32, 0x10) + @as(u32, irq_line) * 2;
    const irq_state = ioapic_lock.lockIrqSave();
    const val = ioapicRead(reg);
    ioapicWrite(reg, val & ~@as(u32, 1 << 16));
    ioapic_lock.unlockIrqRestore(irq_state);
}

/// Look up which IRQ line, if any, is assigned to the given device region.
pub fn findIrqForDevice(device: *DeviceRegion) ?u8 {
    for (irq_table, 0..) |dev_ptr, i| {
        if (dev_ptr == device) return @truncate(i);
    }
    return null;
}

/// Read a 32-bit register from the I/O APIC via the indirect MMIO interface.
/// 82093AA I/O APIC Datasheet, §3.1 "I/O APIC Registers" — IOREGSEL at
/// base+0x00 selects the register index; IOWIN at base+0x10 is the data window.
fn ioapicRead(reg: u32) u32 {
    const sel: *volatile u32 = @ptrFromInt(ioapic_base);
    const win: *const volatile u32 = @ptrFromInt(ioapic_base + 0x10);
    sel.* = reg;
    return win.*;
}

/// Write a 32-bit register to the I/O APIC via the indirect MMIO interface.
/// 82093AA I/O APIC Datasheet, §3.1 "I/O APIC Registers" — IOREGSEL at
/// base+0x00 selects the register index; IOWIN at base+0x10 is the data window.
fn ioapicWrite(reg: u32, val: u32) void {
    const sel: *volatile u32 = @ptrFromInt(ioapic_base);
    const win: *volatile u32 = @ptrFromInt(ioapic_base + 0x10);
    sel.* = reg;
    win.* = val;
}
