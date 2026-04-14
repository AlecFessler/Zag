//! Aarch64 VM exit dispatch.
//!
//! Mirrors `kernel/arch/x64/kvm/exit_handler.zig`. Called by the vCPU
//! run loop after every `vm_hw.vmResume` to decide whether an exit is
//! handled inline by the kernel or delivered to the VMM via the
//! VmExitBox.
//!
//! Inline-handled (no VMM involvement, see spec §4.2.9):
//!   - `sysreg_trap` (EC=0x18) covered by `vm.policy.id_reg_responses`
//!     or `vm.policy.sysreg_policies`. Mirrors x86 CPUID/CR inline.
//!   - `stage2_fault` (EC=0x20/0x24) on a GICD/GICR MMIO page —
//!     dispatched via `Vm.tryHandleMmio` to the in-kernel vGIC.
//!   - `wfi_wfe` — converted to a scheduler yield inline.
//!
//! Delivered to VMM (spec §4.2.10):
//!   - `stage2_fault` on any other guest-physical address (unmapped →
//!     VMM decides to map or inject a fault).
//!   - `hvc` / `smc`.
//!   - `sysreg_trap` not covered by policy.
//!   - `halt` / `shutdown` / `unknown`.

const zag = @import("zag");

const kvm = zag.arch.aarch64.kvm;
const exit_box = kvm.exit_box;
const vcpu_mod = kvm.vcpu;
const vm_hw = zag.arch.aarch64.vm;

const VCpu = vcpu_mod.VCpu;

/// Handle a VM exit. Called from the vCPU run loop after `vmResume()`
/// returns. Either resolves the exit inline (so the loop re-enters guest
/// mode) or transitions the vCPU to `.exited` and queues it on the
/// exit box for VMM delivery.
pub fn handleExit(vcpu_obj: *VCpu, exit_info: vm_hw.VmExitInfo) void {
    const vm_obj = vcpu_obj.vm;

    switch (exit_info) {
        .stage2_fault => |fault| {
            // GICD / GICR MMIO is dispatched and PC-advanced inside the Vm.
            if (vm_obj.tryHandleMmio(vcpu_obj, fault)) return;
            // Unmapped IPA — fall through to VMM delivery so it can map
            // the region or inject a fault.
        },
        .sysreg_trap => |trap| {
            // ID register lookup — analogous to x86 CPUID inline handling.
            if (lookupIdReg(&vm_obj.policy, trap)) |value| {
                if (trap.is_read) writeRt(vcpu_obj, trap.rt, value);
                vcpu_obj.guest_state.pc +%= 4;
                return;
            }
            // General sysreg policy (read_value / write_mask).
            if (lookupSysregPolicy(&vm_obj.policy, trap)) |entry| {
                if (trap.is_read) {
                    writeRt(vcpu_obj, trap.rt, entry.read_value);
                } else if (entry.write_mask != 0) {
                    // Writes with a non-zero mask are silently swallowed
                    // (we don't store the value anywhere yet — TODO when
                    // a real per-policy back-store is needed).
                }
                vcpu_obj.guest_state.pc +%= 4;
                return;
            }
            // No policy match — fall through to VMM delivery.
        },
        .wfi_wfe => {
            // Yielding inline matches the host behavior the guest expects.
            // ARM ARM B1.5: WFI is a hint, not a state change. Advance PC
            // and let the scheduler pick another thread.
            vcpu_obj.guest_state.pc +%= 4;
            zag.sched.scheduler.yield();
            return;
        },
        else => {},
    }

    // VMM-handled exit: snapshot state and enqueue or deliver.
    vcpu_obj.storeState(.exited);
    exit_box.queueOrDeliver(vm_obj.exitBox(), vm_obj, vcpu_obj);
}

fn writeRt(vcpu_obj: *VCpu, rt: u5, value: u64) void {
    if (rt == 31) return; // XZR
    const base: [*]u64 = @ptrCast(&vcpu_obj.guest_state);
    base[rt] = value;
}

fn lookupIdReg(policy: *const vm_hw.VmPolicy, trap: vm_hw.VmExitInfo.SysregTrap) ?u64 {
    for (policy.id_reg_responses[0..policy.num_id_reg_responses]) |e| {
        if (e.op0 == @as(u8, trap.op0) and
            e.op1 == @as(u8, trap.op1) and
            e.crn == @as(u8, trap.crn) and
            e.crm == @as(u8, trap.crm) and
            e.op2 == @as(u8, trap.op2))
        {
            return e.value;
        }
    }
    return null;
}

fn lookupSysregPolicy(
    policy: *const vm_hw.VmPolicy,
    trap: vm_hw.VmExitInfo.SysregTrap,
) ?vm_hw.VmPolicy.SysregPolicy {
    for (policy.sysreg_policies[0..policy.num_sysreg_policies]) |e| {
        if (e.op0 == @as(u8, trap.op0) and
            e.op1 == @as(u8, trap.op1) and
            e.crn == @as(u8, trap.crn) and
            e.crm == @as(u8, trap.crm) and
            e.op2 == @as(u8, trap.op2))
        {
            return e;
        }
    }
    return null;
}
