/// VM exit dispatch -- called by the arch layer (via the vCPU entry point)
/// when a VM exit fires. Classifies exits as kernel-handled or VMM-handled.
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const exit_box = zag.kvm.exit_box;
const guest_memory = zag.kvm.guest_memory;
const vcpu_mod = zag.kvm.vcpu;

const VCpu = vcpu_mod.VCpu;

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
            // LAPIC/IOAPIC MMIO is dispatched + advanced inside the Vm.
            if (vm_obj.tryHandleMmio(vcpu_obj, ept.guest_phys)) return;
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

    // VMM-handled exit: snapshot state and enqueue or deliver to receiver.
    vcpu_obj.storeState(.exited);
    exit_box.queueOrDeliver(vm_obj.exitBox(), vm_obj, vcpu_obj);
}

fn lookupCpuidPolicy(policy: *const arch.VmPolicy, leaf: u32, subleaf: u32) ?arch.VmPolicy.CpuidPolicy {
    for (policy.cpuid_responses[0..policy.num_cpuid_responses]) |entry| {
        if (entry.leaf == leaf and entry.subleaf == subleaf) return entry;
    }
    return null;
}
