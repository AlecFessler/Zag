//! x86-64 vCPU run-loop driver.
//!
//! Stitches the per-arch VMX/SVM `vmResume` to the kernel's per-vCPU
//! storage (`kvm.vcpu.VcpuArchState`) and the per-VM control state
//! (VMCS on Intel, VMCB on AMD) pinned on `VirtualMachine.arch_state`
//! via `kvm.vm.allocVmArchState`. Exit reasons are decoded by the
//! per-arch backend into the cross-arch `vm_hw.VmExitInfo`; this module
//! folds that into the spec-v3 §[vm_exit_state] sub-code + 3-vreg
//! payload the scheduler hands to `sched.port.fireVmExit`.

const zag = @import("zag");

const cpu_dispatch = zag.arch.dispatch.cpu;
const kvm_vcpu = zag.arch.x64.kvm.vcpu;
const kvm_vm = zag.arch.x64.kvm.vm;
const vm_hw = zag.arch.x64.vm;
const x64_interrupts = zag.arch.x64.interrupts;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GuestState = vm_hw.GuestState;
const PAddr = zag.memory.address.PAddr;
const VmExitDelivery = zag.arch.dispatch.vm.VmExitDelivery;

// §[vm_exit_state] x86-64 sub-codes (mirror of the table in the spec).
const SUBCODE_CPUID: u8 = 0;
const SUBCODE_IO: u8 = 1;
const SUBCODE_MMIO: u8 = 2;
const SUBCODE_CR: u8 = 3;
const SUBCODE_MSR_R: u8 = 4;
const SUBCODE_MSR_W: u8 = 5;
const SUBCODE_EPT: u8 = 6;
const SUBCODE_EXCEPT: u8 = 7;
const SUBCODE_INTWIN: u8 = 8;
const SUBCODE_HLT: u8 = 9;
const SUBCODE_SHUTDOWN: u8 = 10;
const SUBCODE_TRIPLE: u8 = 11;
const SUBCODE_UNKNOWN: u8 = 12;

/// Enter the guest bound to `vcpu_ec` and return on the next VM exit.
/// Returns `null` if the VM or its arch state is missing (creator
/// teardown raced us, or the platform doesn't support hardware virt).
pub fn enterGuest(vcpu_ec: *ExecutionContext) ?VmExitDelivery {
    if (!vm_hw.vmSupported()) return null;

    // Resolve the VM's per-vCPU state and the VM's control-state PAddr.
    const arch_state = kvm_vcpu.archStateOf(vcpu_ec) orelse return null;

    // Defer real VMLAUNCH/VMRUN until the VMM has supplied initial
    // guest state via reply. Otherwise we would VM-enter with a zeroed
    // GuestState and trip VM-entry consistency checks. The synthetic-
    // exit fallback is the spec-test path before reply→GuestState
    // writeback is wired; once that lands, this guard flips on reply.
    if (!arch_state.started) return null;

    const vm_ref = vcpu_ec.vm orelse return null;
    // self-alive: the vCPU EC holds a SlabRef on its VM for its lifetime;
    // the run loop is the only consumer that needs the live pointer.
    const vm_ptr = vm_ref.lock(@src()) catch return null;
    const ctrl_phys = ctrlPhysFor(vm_ptr);
    vm_ref.unlock();

    const vmcs_paddr = ctrl_phys orelse return null;

    // Pre-VMRUN: deliver any pending interrupt vector queued in the VM's
    // emulated LAPIC (driven by IOAPIC pin asserts via `vm_inject_irq`).
    // The LAPIC tracks IRR/ISR per Intel SDM Vol 3 §13; if a deliverable
    // vector is pending and the guest is interruptible (RFLAGS.IF=1, no
    // prior EVENTINJ on AMD), we call `injectInterrupt` to set up the
    // VMCS/VMCB event-injection field and acknowledge the LAPIC.
    deliverPendingInterrupts(vm_ptr, &arch_state.guest_state);

    // Run the guest until the next VM exit. On return, GuestState +
    // last_exit are populated.
    const exit_info = vm_hw.vmResume(&arch_state.guest_state, vmcs_paddr, &arch_state.guest_fxsave);
    arch_state.last_exit = exit_info;

    return decodeDelivery(exit_info, &arch_state.guest_state);
}

// ---------------------------------------------------------------------------
// §[vm_exit_state] vreg layout (x86-64)
// ---------------------------------------------------------------------------
//
// Receiver-side stack layout after recv with sufficient reservation: the
// kernel writes [user_rsp + (N-13)*8] = vreg N for 14 ≤ N ≤ 127. The
// applyReplyStateToVcpu / populateVmExitVregs helpers below read/write
// the matching offsets to project guest state onto the receiver and
// commit receiver modifications back to GuestState.

const VREG14_RIP_OFF: u64 = 8; // (14-13)*8
const VREG15_RFLAGS_OFF: u64 = 16;
const VREG16_RSP_OFF: u64 = 24;
const VREG17_RCX_OFF: u64 = 32;
const VREG18_R11_OFF: u64 = 40;
const VREG19_CR0_OFF: u64 = 48;
const VREG20_CR2_OFF: u64 = 56;
const VREG21_CR3_OFF: u64 = 64;
const VREG22_CR4_OFF: u64 = 72;
// vreg 23 = CR8 (not in GuestState; read-write but ignored)
// vreg 24 = EFER, vreg 25 = APIC_BASE
const VREG24_EFER_OFF: u64 = 88;
// Segment band: vregs 26..41 = 8 segs × 2 vregs each.
// Layout: vreg(26+2i) = base, vreg(26+2i+1) = {limit u32, selector u16, access_rights u16}.
const VREG26_CS_BASE_OFF: u64 = 104;
// GDTR/IDTR band: vregs 42..43, 44..45.
const VREG42_GDTR_BASE_OFF: u64 = 232;
const VREG43_GDTR_LIMIT_OFF: u64 = 240;
const VREG44_IDTR_BASE_OFF: u64 = 248;
const VREG45_IDTR_LIMIT_OFF: u64 = 256;
// MSR band: vregs 46..55.
const VREG46_STAR_OFF: u64 = 264;
const VREG47_LSTAR_OFF: u64 = 272;
const VREG48_CSTAR_OFF: u64 = 280;
const VREG49_SFMASK_OFF: u64 = 288;
const VREG50_KERNEL_GS_BASE_OFF: u64 = 296;
const VREG51_SYSENTER_CS_OFF: u64 = 304;
const VREG52_SYSENTER_ESP_OFF: u64 = 312;
const VREG53_SYSENTER_EIP_OFF: u64 = 320;
const VREG54_PAT_OFF: u64 = 328;
// vreg 55 = TSC_AUX (not in GuestState)
// DR band: vregs 56..61.
const VREG56_DR0_OFF: u64 = 344;
const VREG60_DR6_OFF: u64 = 376;
const VREG61_DR7_OFF: u64 = 384;
// Exit sub-code + payload: vregs 70..73.
const VREG70_EXIT_SUBCODE_OFF: u64 = 456;
const VREG71_EXIT_PAYLOAD_0_OFF: u64 = 464;
const VREG72_EXIT_PAYLOAD_1_OFF: u64 = 472;
const VREG73_EXIT_PAYLOAD_2_OFF: u64 = 480;

fn loadU64(rsp: u64, off: u64) u64 {
    const ptr: *const u64 = @ptrFromInt(rsp + off);
    return ptr.*;
}
fn storeU64(rsp: u64, off: u64, value: u64) void {
    const ptr: *u64 = @ptrFromInt(rsp + off);
    ptr.* = value;
}

/// Project the receiver's modified §[vm_exit_state] vregs back onto the
/// vCPU's GuestState. Called from `port.consumeReply` when the
/// originating event was vm_exit, before the vCPU's `resumeFromReply`.
/// Receiver MUST be the running EC on the current core (so CR3 already
/// references the receiver's address space; SMAP gates the user-stack
/// loads via STAC/CLAC).
///
/// On first successful reply this also flips `arch_state.started = true`,
/// arming the next `enterGuest` to actually execute VMLAUNCH/VMRUN with
/// the supplied initial guest state.
pub fn applyReplyStateToVcpu(receiver: *ExecutionContext, vcpu_ec: *ExecutionContext) void {
    const arch_state = kvm_vcpu.archStateOf(vcpu_ec) orelse return;
    const gs = &arch_state.guest_state;
    const recv_frame = receiver.iret_frame orelse receiver.ctx;

    // vregs 1..13 — register-backed. Read straight from receiver's
    // saved iret frame into the vCPU's GuestState GPR slots.
    gs.rax = recv_frame.regs.rax;
    gs.rbx = recv_frame.regs.rbx;
    gs.rdx = recv_frame.regs.rdx;
    gs.rbp = recv_frame.regs.rbp;
    gs.rsi = recv_frame.regs.rsi;
    gs.rdi = recv_frame.regs.rdi;
    gs.r8 = recv_frame.regs.r8;
    gs.r9 = recv_frame.regs.r9;
    gs.r10 = recv_frame.regs.r10;
    gs.r12 = recv_frame.regs.r12;
    gs.r13 = recv_frame.regs.r13;
    gs.r14 = recv_frame.regs.r14;
    gs.r15 = recv_frame.regs.r15;

    // vregs 14..73 live on the receiver's user stack at the rsp captured
    // by the syscall trampoline. SMAP gates the loads.
    const rsp = recv_frame.rsp;
    cpu_dispatch.userAccessBegin();
    defer cpu_dispatch.userAccessEnd();

    gs.rip = loadU64(rsp, VREG14_RIP_OFF);
    gs.rflags = loadU64(rsp, VREG15_RFLAGS_OFF);
    gs.rsp = loadU64(rsp, VREG16_RSP_OFF);
    gs.rcx = loadU64(rsp, VREG17_RCX_OFF);
    gs.r11 = loadU64(rsp, VREG18_R11_OFF);
    gs.cr0 = loadU64(rsp, VREG19_CR0_OFF);
    gs.cr2 = loadU64(rsp, VREG20_CR2_OFF);
    gs.cr3 = loadU64(rsp, VREG21_CR3_OFF);
    gs.cr4 = loadU64(rsp, VREG22_CR4_OFF);
    gs.efer = loadU64(rsp, VREG24_EFER_OFF);

    // Segments: vregs 26..41 = 8 segs × 2 vregs each.
    // {base u64, {limit u32, selector u16, access_rights u16}}
    loadSegment(rsp, VREG26_CS_BASE_OFF + 0 * 16, &gs.cs);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 1 * 16, &gs.ds);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 2 * 16, &gs.es);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 3 * 16, &gs.fs);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 4 * 16, &gs.gs);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 5 * 16, &gs.ss);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 6 * 16, &gs.tr);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 7 * 16, &gs.ldtr);

    // GDTR / IDTR
    gs.gdtr_base = loadU64(rsp, VREG42_GDTR_BASE_OFF);
    gs.gdtr_limit = @truncate(loadU64(rsp, VREG43_GDTR_LIMIT_OFF));
    gs.idtr_base = loadU64(rsp, VREG44_IDTR_BASE_OFF);
    gs.idtr_limit = @truncate(loadU64(rsp, VREG45_IDTR_LIMIT_OFF));

    // MSRs vregs 46..54 (vreg 55 = TSC_AUX, not in GuestState).
    gs.star = loadU64(rsp, VREG46_STAR_OFF);
    gs.lstar = loadU64(rsp, VREG47_LSTAR_OFF);
    gs.cstar = loadU64(rsp, VREG48_CSTAR_OFF);
    gs.sfmask = loadU64(rsp, VREG49_SFMASK_OFF);
    gs.kernel_gs_base = loadU64(rsp, VREG50_KERNEL_GS_BASE_OFF);
    gs.sysenter_cs = loadU64(rsp, VREG51_SYSENTER_CS_OFF);
    gs.sysenter_esp = loadU64(rsp, VREG52_SYSENTER_ESP_OFF);
    gs.sysenter_eip = loadU64(rsp, VREG53_SYSENTER_EIP_OFF);
    gs.pat = loadU64(rsp, VREG54_PAT_OFF);

    // DRs vregs 56..61 (DR0..DR3 not in GuestState — skipped; DR6/DR7 are).
    gs.dr6 = loadU64(rsp, VREG60_DR6_OFF);
    gs.dr7 = loadU64(rsp, VREG61_DR7_OFF);

    arch_state.started = true;
}

fn loadSegment(rsp: u64, off: u64, seg: *GuestState.SegmentReg) void {
    seg.base = loadU64(rsp, off);
    const packed_word = loadU64(rsp, off + 8);
    seg.limit = @truncate(packed_word);
    seg.selector = @truncate(packed_word >> 32);
    seg.access_rights = @truncate(packed_word >> 48);
}

fn storeSegment(rsp: u64, off: u64, seg: *const GuestState.SegmentReg) void {
    storeU64(rsp, off, seg.base);
    const packed_word: u64 =
        @as(u64, seg.limit) |
        (@as(u64, seg.selector) << 32) |
        (@as(u64, seg.access_rights) << 48);
    storeU64(rsp, off + 8, packed_word);
}

/// Write the suspending vCPU's GuestState onto the receiver's
/// §[vm_exit_state] vreg slots. Called from `port.deliverEvent` when
/// the suspending event is vm_exit. Receiver MUST be the running EC on
/// the current core (CR3 = receiver's address space; SMAP STAC/CLAC
/// brackets the user-stack stores).
///
/// Companion to `applyReplyStateToVcpu`. Together they implement the
/// spec-v3 cross-domain guest-state-via-vregs contract.
pub fn populateVmExitVregs(
    receiver: *ExecutionContext,
    vcpu_ec: *ExecutionContext,
    subcode: u8,
    payload: [3]u64,
) void {
    const arch_state = kvm_vcpu.archStateOf(vcpu_ec) orelse return;
    const gs = &arch_state.guest_state;
    const recv_frame = receiver.iret_frame orelse receiver.ctx;

    // vregs 1..13 — register-backed.
    recv_frame.regs.rax = gs.rax;
    recv_frame.regs.rbx = gs.rbx;
    recv_frame.regs.rdx = gs.rdx;
    recv_frame.regs.rbp = gs.rbp;
    recv_frame.regs.rsi = gs.rsi;
    recv_frame.regs.rdi = gs.rdi;
    recv_frame.regs.r8 = gs.r8;
    recv_frame.regs.r9 = gs.r9;
    recv_frame.regs.r10 = gs.r10;
    recv_frame.regs.r12 = gs.r12;
    recv_frame.regs.r13 = gs.r13;
    recv_frame.regs.r14 = gs.r14;
    recv_frame.regs.r15 = gs.r15;

    const rsp = recv_frame.rsp;
    cpu_dispatch.userAccessBegin();
    defer cpu_dispatch.userAccessEnd();

    storeU64(rsp, VREG14_RIP_OFF, gs.rip);
    storeU64(rsp, VREG15_RFLAGS_OFF, gs.rflags);
    storeU64(rsp, VREG16_RSP_OFF, gs.rsp);
    storeU64(rsp, VREG17_RCX_OFF, gs.rcx);
    storeU64(rsp, VREG18_R11_OFF, gs.r11);
    storeU64(rsp, VREG19_CR0_OFF, gs.cr0);
    storeU64(rsp, VREG20_CR2_OFF, gs.cr2);
    storeU64(rsp, VREG21_CR3_OFF, gs.cr3);
    storeU64(rsp, VREG22_CR4_OFF, gs.cr4);
    storeU64(rsp, VREG24_EFER_OFF, gs.efer);

    storeSegment(rsp, VREG26_CS_BASE_OFF + 0 * 16, &gs.cs);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 1 * 16, &gs.ds);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 2 * 16, &gs.es);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 3 * 16, &gs.fs);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 4 * 16, &gs.gs);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 5 * 16, &gs.ss);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 6 * 16, &gs.tr);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 7 * 16, &gs.ldtr);

    storeU64(rsp, VREG42_GDTR_BASE_OFF, gs.gdtr_base);
    storeU64(rsp, VREG43_GDTR_LIMIT_OFF, @as(u64, gs.gdtr_limit));
    storeU64(rsp, VREG44_IDTR_BASE_OFF, gs.idtr_base);
    storeU64(rsp, VREG45_IDTR_LIMIT_OFF, @as(u64, gs.idtr_limit));

    storeU64(rsp, VREG46_STAR_OFF, gs.star);
    storeU64(rsp, VREG47_LSTAR_OFF, gs.lstar);
    storeU64(rsp, VREG48_CSTAR_OFF, gs.cstar);
    storeU64(rsp, VREG49_SFMASK_OFF, gs.sfmask);
    storeU64(rsp, VREG50_KERNEL_GS_BASE_OFF, gs.kernel_gs_base);
    storeU64(rsp, VREG51_SYSENTER_CS_OFF, gs.sysenter_cs);
    storeU64(rsp, VREG52_SYSENTER_ESP_OFF, gs.sysenter_esp);
    storeU64(rsp, VREG53_SYSENTER_EIP_OFF, gs.sysenter_eip);
    storeU64(rsp, VREG54_PAT_OFF, gs.pat);

    storeU64(rsp, VREG60_DR6_OFF, gs.dr6);
    storeU64(rsp, VREG61_DR7_OFF, gs.dr7);

    storeU64(rsp, VREG70_EXIT_SUBCODE_OFF, @as(u64, subcode));
    storeU64(rsp, VREG71_EXIT_PAYLOAD_0_OFF, payload[0]);
    storeU64(rsp, VREG72_EXIT_PAYLOAD_1_OFF, payload[1]);
    storeU64(rsp, VREG73_EXIT_PAYLOAD_2_OFF, payload[2]);
}

fn deliverPendingInterrupts(vm_ptr: *zag.capdom.virtual_machine.VirtualMachine, gs: *vm_hw.GuestState) void {
    // Skip if guest interrupts are masked. On AMD, also skip if a prior
    // EVENTINJ is still pending (the guest hasn't entered yet).
    if ((gs.rflags & (1 << 9)) == 0) return;
    if (gs.pending_eventinj != 0) return;

    const vector = vm_ptr.lapic.getPendingVector() orelse return;
    vm_hw.injectInterrupt(gs, .{
        .vector = vector,
        .interrupt_type = 0, // external interrupt
        .error_code_valid = false,
    });
    vm_ptr.lapic.acceptInterrupt(vector);
}

fn ctrlPhysFor(vm_ptr: *zag.capdom.virtual_machine.VirtualMachine) ?PAddr {
    const erased = vm_ptr.arch_state orelse return null;
    const cell: *kvm_vm.CtrlStateCell = @ptrCast(@alignCast(erased));
    return cell.ctrl_phys;
}

fn decodeDelivery(exit: vm_hw.VmExitInfo, gs: *const vm_hw.GuestState) VmExitDelivery {
    return switch (exit) {
        .cpuid => |c| .{
            .subcode = SUBCODE_CPUID,
            .payload = .{
                (@as(u64, c.subleaf) << 32) | @as(u64, c.leaf),
                0,
                0,
            },
        },
        .io => |io| .{
            .subcode = SUBCODE_IO,
            .payload = .{
                io.next_rip,
                // {value u32, port u16, size u8, is_write u8}
                @as(u64, io.value) |
                    (@as(u64, io.port) << 32) |
                    (@as(u64, io.size) << 48) |
                    (@as(u64, @intFromBool(io.is_write)) << 56),
                0,
            },
        },
        .mmio => |m| .{
            .subcode = SUBCODE_MMIO,
            .payload = .{
                m.addr,
                m.value,
                @as(u64, m.size) | (@as(u64, @intFromBool(m.is_write)) << 8),
            },
        },
        .cr_access => |cr| .{
            .subcode = SUBCODE_CR,
            .payload = .{
                cr.value,
                @as(u64, cr.cr_num) |
                    (@as(u64, @intFromBool(cr.is_write)) << 4) |
                    (@as(u64, cr.gpr) << 5),
                0,
            },
        },
        .msr_read => |m| .{
            .subcode = SUBCODE_MSR_R,
            .payload = .{ m.value, @as(u64, m.msr), 0 },
        },
        .msr_write => |m| .{
            .subcode = SUBCODE_MSR_W,
            .payload = .{ m.value, @as(u64, m.msr), 0 },
        },
        .ept_violation => |e| .{
            .subcode = SUBCODE_EPT,
            .payload = .{
                e.guest_phys,
                @as(u64, @intFromBool(e.is_read)) |
                    (@as(u64, @intFromBool(e.is_write)) << 1) |
                    (@as(u64, @intFromBool(e.is_exec)) << 2),
                0,
            },
        },
        .exception => |e| .{
            .subcode = SUBCODE_EXCEPT,
            .payload = .{ @as(u64, e.vector), e.error_code, 0 },
        },
        .interrupt_window => .{
            .subcode = SUBCODE_INTWIN,
            .payload = .{ 0, 0, 0 },
        },
        .hlt => .{
            .subcode = SUBCODE_HLT,
            .payload = .{ gs.rip, 0, 0 },
        },
        .shutdown => .{
            .subcode = SUBCODE_SHUTDOWN,
            .payload = .{ 0, 0, 0 },
        },
        .triple_fault => .{
            .subcode = SUBCODE_TRIPLE,
            .payload = .{ 0, 0, 0 },
        },
        .unknown => |code| .{
            .subcode = SUBCODE_UNKNOWN,
            .payload = .{ code, 0, 0 },
        },
    };
}
