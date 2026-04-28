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

const kvm_vcpu = zag.arch.x64.kvm.vcpu;
const kvm_vm = zag.arch.x64.kvm.vm;
const vm_hw = zag.arch.x64.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
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
