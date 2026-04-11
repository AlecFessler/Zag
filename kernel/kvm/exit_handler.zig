/// VM exit dispatch -- called by the arch layer (via the vCPU entry point)
/// when a VM exit fires. Classifies exits as kernel-handled or VMM-handled.
const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const guest_memory = zag.kvm.guest_memory;
const mmio_decode = zag.kvm.mmio_decode;
const sched = zag.sched.scheduler;
const vcpu_mod = zag.kvm.vcpu;

const ioapic_mod = zag.kvm.ioapic;
const lapic_mod = zag.kvm.lapic;

const Thread = zag.sched.thread.Thread;
const VCpu = vcpu_mod.VCpu;
const Vm = zag.kvm.vm.Vm;
const VmExitBox = zag.kvm.exit_box.VmExitBox;

pub const ExitHandler = struct {
    _unused: u8 = 0,
};

/// Handle a VM exit. Called from the vCPU thread entry point after
/// arch.vmResume() returns.
///
/// If the exit can be handled inline (demand page, policy-covered CPUID/CR,
/// LAPIC/IOAPIC MMIO), resolves it and returns (the vCPU loop will re-enter
/// guest mode).
/// If the exit requires VMM involvement, snapshots state, enqueues on the
/// exit box, and transitions the vCPU to .exited state.
pub fn handleExit(vcpu_obj: *VCpu, exit_info: arch.VmExitInfo) void {
    const vm_obj = vcpu_obj.vm;

    // Try kernel-handled exits first
    switch (exit_info) {
        .ept_violation => |ept| {
            // Check LAPIC page (0xFEE00000)
            if (ept.guest_phys >= lapic_mod.APIC_BASE and ept.guest_phys < lapic_mod.APIC_BASE + 0x1000) {
                if (handleLapicMmio(vcpu_obj, ept.guest_phys)) return;
            }
            // Check IOAPIC page (0xFEC00000)
            if (ept.guest_phys >= ioapic_mod.IOAPIC_BASE and ept.guest_phys < ioapic_mod.IOAPIC_BASE + 0x1000) {
                if (handleIoapicMmio(vcpu_obj, ept.guest_phys)) return;
            }
            // Check if this is a demand-paged region
            if (guest_memory.handleFault(&vm_obj.guest_mem, vm_obj.arch_structures, ept.guest_phys)) {
                // Handled inline -- resume guest
                return;
            }
            // Unmapped region -- fall through to VMM delivery
        },
        .cpuid => |cpuid_exit| {
            // Check policy table for pre-configured response
            if (lookupCpuidPolicy(&vm_obj.policy, cpuid_exit.leaf, cpuid_exit.subleaf)) |response| {
                // Write response into guest state and advance RIP past CPUID (2 bytes)
                vcpu_obj.guest_state.rax = response.eax;
                vcpu_obj.guest_state.rbx = response.ebx;
                vcpu_obj.guest_state.rcx = response.ecx;
                vcpu_obj.guest_state.rdx = response.edx;
                vcpu_obj.guest_state.rip += 2;
                return;
            }
            // No policy match -- fall through to VMM delivery
        },
        .cr_access => |cr_exit| {
            // TODO: implement inline CR policy handling (return configured
            // value for reads, apply write_mask for writes, advance RIP).
            // For now, all CR accesses fall through to VMM delivery.
            _ = cr_exit;
        },
        .interrupt_window => {
            // VMEXIT_VINTR: guest IF just became 1. Try to inject a pending
            // interrupt. The vCPU entry loop will handle injection before
            // the next VMRUN. Just return to re-enter the loop.
            return;
        },
        .unknown => |code| {
            // VMEXIT_INTR (0x060) / VMEXIT_NMI (0x061): physical interrupt
            // or NMI intercepted. The host handler has already executed on
            // #VMEXIT -- just return so the vCPU loop re-enters the guest.
            if (code == 0x060 or code == 0x061) return;
            // VMEXIT_VINTR (0x064): virtual interrupt window.
            if (code == 0x064) return;
        },
        else => {},
    }

    // VMM-handled exit: snapshot state and enqueue
    vcpu_obj.state = .exited;

    const box = &vm_obj.exit_box;
    box.lock.lock();

    if (box.isReceiving()) {
        // Direct delivery to blocked receiver
        const receiver = box.takeReceiverLocked();
        box.lock.unlock();
        deliverToReceiver(vm_obj, vcpu_obj, receiver);
    } else {
        // Enqueue for later vm_recv
        box.enqueueLocked(vcpu_obj.thread);
        box.lock.unlock();
    }
}

/// Handle LAPIC MMIO access in-kernel. Decodes the instruction at guest RIP,
/// dispatches to the kernel LAPIC, writes the result back, and advances RIP.
/// Returns true if handled, false to fall through to VMM.
fn handleLapicMmio(vcpu_obj: *VCpu, guest_phys: u64) bool {
    const op = mmio_decode.decode(vcpu_obj.vm, &vcpu_obj.guest_state) orelse return false;
    const offset: u32 = @truncate(guest_phys - lapic_mod.APIC_BASE);
    const vm_obj = vcpu_obj.vm;

    if (op.is_write) {
        vm_obj.lapic.write(offset, op.value);
    } else {
        const value = vm_obj.lapic.read(offset);
        mmio_decode.writeGpr(&vcpu_obj.guest_state, op.reg, @as(u64, value));
    }
    vcpu_obj.guest_state.rip += op.len;
    return true;
}

/// Handle IOAPIC MMIO access in-kernel. Decodes the instruction at guest RIP,
/// dispatches to the kernel IOAPIC, writes the result back, and advances RIP.
/// Returns true if handled, false to fall through to VMM.
fn handleIoapicMmio(vcpu_obj: *VCpu, guest_phys: u64) bool {
    const op = mmio_decode.decode(vcpu_obj.vm, &vcpu_obj.guest_state) orelse return false;
    const offset: u32 = @truncate(guest_phys - ioapic_mod.IOAPIC_BASE);
    const vm_obj = vcpu_obj.vm;

    if (op.is_write) {
        vm_obj.ioapic.write(offset, op.value);
    } else {
        const value = vm_obj.ioapic.read(offset);
        mmio_decode.writeGpr(&vcpu_obj.guest_state, op.reg, @as(u64, value));
    }
    vcpu_obj.guest_state.rip += op.len;
    return true;
}

fn deliverToReceiver(vm_obj: *Vm, vcpu_obj: *VCpu, receiver: *Thread) void {
    const owner = vm_obj.owner;
    const handle_id = owner.findThreadHandle(vcpu_obj.thread) orelse return;

    // Find vCPU index and mark pending
    for (vm_obj.vcpus[0..vm_obj.num_vcpus], 0..) |v, i| {
        if (v == vcpu_obj) {
            vm_obj.exit_box.lock.lock();
            vm_obj.exit_box.markPendingLocked(@intCast(i));
            vm_obj.exit_box.lock.unlock();
            break;
        }
    }

    vcpu_obj.state = .waiting_reply;

    // Wait until receiver is off CPU and has saved its context.
    while (receiver.on_cpu.load(.acquire)) std.atomic.spinLoopHint();

    // Write exit info into receiver's saved buf_ptr (RDI from syscall entry)
    const buf_ptr = receiver.ctx.regs.rdi;
    zag.kvm.exit_box.writeExitMessageToUser(owner, buf_ptr, handle_id, vcpu_obj);

    // Set return value
    receiver.ctx.regs.rax = handle_id;

    // Wake the receiver
    receiver.state = .ready;
    const target_core = if (receiver.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
    sched.enqueueOnCore(target_core, receiver);
}

fn lookupCpuidPolicy(policy: *const arch.VmPolicy, leaf: u32, subleaf: u32) ?arch.VmPolicy.CpuidPolicy {
    for (policy.cpuid_responses[0..policy.num_cpuid_responses]) |entry| {
        if (entry.leaf == leaf and entry.subleaf == subleaf) return entry;
    }
    return null;
}

fn lookupCrPolicy(policy: *const arch.VmPolicy, cr_num: u4, is_write: bool) ?arch.VmPolicy.CrPolicy {
    _ = is_write;
    for (policy.cr_policies[0..policy.num_cr_policies]) |entry| {
        if (entry.cr_num == cr_num) return entry;
    }
    return null;
}
