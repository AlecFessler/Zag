//! Aarch64 VM exit dispatch.
//!
//! Mirrors `kernel/arch/x64/kvm/exit_handler.zig`. Called by the vCPU
//! run loop after every `vm_hyp.vmResume` to decide whether an exit is
//! handled inline by the kernel or delivered to the VMM via the
//! VmExitBox.
//!
//! Inline-handled (no VMM involvement, see spec §4.2.9):
//!   - `sysreg_trap` (EC=0x18) covered by `vm.policy.id_reg_responses`
//!     or `vm.policy.sysreg_policies`. Mirrors x86 CPUID/CR inline.
//!   - `stage2_fault` (EC=0x20/0x24) on a GICD/GICR MMIO page —
//!     dispatched via `Vm.tryHandleMmio` to the in-kernel vGIC.
//!   - `wfi_wfe` — converted to a scheduler yield inline.
//!   - `hvc` carrying a PSCI SMCCC function ID — dispatched to
//!     `kvm.psci`; on `not_supported` the call completes inline with
//!     the PSCI error code in x0.
//!
//! Delivered to VMM (spec §4.2.10):
//!   - `stage2_fault` on any other guest-physical address (unmapped →
//!     VMM decides to map or inject a fault).
//!   - `hvc` / `smc` outside the PSCI window (SMCCC pass-through).
//!   - `sysreg_trap` not covered by policy.
//!   - `halt` / `shutdown` / `unknown`.
//!
//! Milestone M2 extended this file to do a full ESR_EL2 ISS decode
//! (ARM ARM D13.2.39, Table D13-45 / Table D13-46) for EC=0x18/0x20/
//! 0x24/0x16/0x17, build a packed (op0,op1,CRn,CRm,op2) sysreg key
//! that matches `stage2.sysregPassthrough`'s convention, and route
//! translation faults vs MMIO emulation separately so #124's stage-2
//! fault router sees a properly classified descriptor.

const zag = @import("zag");

const kvm = zag.arch.aarch64.kvm;
const exit_box = kvm.exit_box;
const psci_mod = kvm.psci;
const vcpu_mod = kvm.vcpu;
const vm_hw = zag.arch.aarch64.vm;

const VCpu = vcpu_mod.VCpu;

/// ARM ARM D13.2.39 Table D13-46 "Data Fault Status Code" /
/// "Instruction Fault Status Code". We only care about the
/// translation-fault rows (0b0001_00 .. 0b0001_11) because those are
/// the fault kind a stage-2 page miss produces and #124's router
/// dispatches them to the guest-memory layer. Permission faults at
/// stage 2 (0b0011_00..0b0011_11) and access-flag faults
/// (0b0010_00..0b0010_11) come through as MMIO emulation requests in
/// this implementation because they originate from a page Zag has
/// already mapped — a typical case is a device region that faulted
/// through because the VMM marked it as emulation-only.
pub const FaultKind = enum {
    translation,
    permission,
    access_flag,
    alignment,
    other,
};

/// Classify the low six bits of a stage-2 fault syndrome (DFSC or
/// IFSC). Reused by both the data-abort and instruction-abort paths.
pub fn classifyFsc(fsc: u8) FaultKind {
    const top = fsc & 0x3C;
    return switch (top) {
        0x04 => .translation, // 0b0001_xx
        0x08 => .access_flag, // 0b0010_xx
        0x0C => .permission, // 0b0011_xx
        0x20 => .alignment, // 0b1000_00
        else => .other,
    };
}

/// Handle a VM exit. Called from the vCPU run loop after `vmResume()`
/// returns. Either resolves the exit inline (so the loop re-enters guest
/// mode) or transitions the vCPU to `.exited` and queues it on the
/// exit box for VMM delivery.
pub fn handleExit(vcpu_obj: *VCpu, exit_info: vm_hw.VmExitInfo) void {
    // handleExit runs on the vCPU's own thread (`vcpu_obj.thread`).
    // While the thread is executing here the Vm it belongs to cannot
    // be destroyed — Vm.destroy waits for its vCPU threads via
    // removeFromAnyRunQueue + exited state.
    // self-alive: owning Vm kept live by the vcpu thread's run loop.
    const vm_obj = vcpu_obj.vm.ptr;

    switch (exit_info) {
        .stage2_fault => |fault| {
            // GICD / GICR MMIO fast-path: dispatched and PC-advanced
            // inside the Vm before any classification. GICv3 §12 register
            // access is strictly emulation-only regardless of the
            // underlying fault kind, so the vGIC handler runs first.
            if (vm_obj.tryHandleMmio(vcpu_obj, fault)) return;

            // M4 #124: classify the stage-2 fault and route.
            //
            // DFSC/IFSC (ARM ARM D13.2.39 Table D13-46) → exit kind:
            //
            //   0b000100..0b000111 (translation L0..L3)   → map_request
            //     Stage-2 miss: no descriptor was installed for this
            //     IPA. The VMM needs to decide whether to back it with
            //     a `map_memory` reply (RAM or passthrough MMIO) or
            //     inject a fault.
            //
            //   0b001000..0b001011 (access-flag L0..L3)   → mmio_emulation
            //   0b001100..0b001111 (permission L0..L3)    → mmio_emulation
            //     A descriptor exists, but the guest access either
            //     failed S2AP / AF, or tripped an attribute mismatch.
            //     In Zag's model this means the VMM deliberately left
            //     the page Device-nGnRnE / read-only / etc. so it
            //     could intercept accesses and decode them — classic
            //     MMIO emulation. `fault.srt`/`fault.access_size`/
            //     `fault.is_write` already contain the ISS-decoded
            //     operand so no re-parse is needed.
            //
            //   anything else (alignment, external, TLB conflict, …)
            //     → forwarded as-is for the VMM to inspect
            //
            // All three cases still exit to the VMM because v1 has no
            // in-kernel demand-pager and no in-kernel MMIO emulator
            // beyond the vGIC fast-path above. The classification is
            // informational today and lets future in-kernel handlers
            // branch on `FaultKind` cheaply without re-decoding ESR.
            // We keep the raw `fault.fsc` on the exit descriptor so
            // the VMM can (and the spec §4.2.10 requires it to) make
            // the same determination without re-reading ESR_EL2.
            switch (classifyFsc(fault.fsc)) {
                .translation => {
                    // map_request — fall through to VMM delivery.
                },
                .permission, .access_flag => {
                    // mmio_emulation — fall through to VMM delivery.
                    // The ISS fields (srt/access_size/is_write/reg64/
                    // sign_extend/acqrel) are already populated by the
                    // M2 decoder and travel with the exit message.
                },
                .alignment, .other => {
                    // Unusual fault: still forwarded so the VMM sees
                    // the raw syndrome and decides policy.
                },
            }
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
        .hvc => |hvc| {
            // HVC with imm16 != 0 is reserved for Zag hypercalls, of
            // which we currently define none. Inject UNDEF back at the
            // guest rather than hand a malformed exit to the VMM.
            if (hvc.imm != 0) {
                injectUndef(vcpu_obj);
                return;
            }
            // imm16 == 0: SMCCC namespace. PSCI calls are handled
            // inline by kvm.psci; anything else is a vendor or
            // standard SMCCC call the VMM is responsible for.
            const fid: u32 = @truncate(vcpu_obj.guest_state.x0);
            if (psci_mod.isPsciFid(fid)) {
                switch (psci_mod.dispatch(vcpu_obj)) {
                    .handled => {
                        // gs.pc was snapshotted from ELR_EL2, which the
                        // hardware sets to (HVC + 4) — the instruction
                        // after the HVC. So gs.pc already points at the
                        // correct resume PC; do NOT add another 4 or we
                        // skip a real instruction. (The VMM-delivered
                        // path below rolls PC back by 4 because the VMM
                        // contract is "exit PC names the trapping HVC,
                        // VMM advances on resume" — that's a separate
                        // rule and does not apply when we resolve inline.)
                        return;
                    },
                    .forward_to_vmm => {},
                }
            }
            // Non-PSCI SMCCC call — deliver as a generic HVC exit.
            //
            // ARM hardware advances ELR_EL2 past the HVC instruction
            // before trapping (D1.10.2), so the guest_state.pc the exit
            // path snapshotted points to PC+4. The VMM contract used by
            // the §4.2 tests (and matching AMD SVM HLT semantics on x86)
            // is that the exit PC names the trapping instruction itself
            // and the VMM advances PC explicitly on resume. Roll PC back
            // to the HVC so a `resume_guest` reply that does not touch
            // PC re-executes the HVC, and one that adds halt_insn_size
            // lands on the next instruction.
            vcpu_obj.guest_state.pc -%= 4;
        },
        .smc => {
            // SMC calls from a non-secure guest are always forwarded to
            // the VMM. We do not answer secure-monitor calls in the
            // kernel because they typically reach EL3 firmware; the
            // VMM decides whether to synthesize a response or inject
            // UNDEF.
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

/// Build the 16-bit packed (op0,op1,CRn,CRm,op2) sysreg key that
/// `stage2.sysregPassthrough` / `isSecurityCriticalSysreg` use. Layout
/// (matched exactly so policy lookups can share keys):
///
///   bits [15:14] Op0
///   bits [13:11] Op1
///   bits [10:7]  CRn
///   bits [6:3]   CRm
///   bits [2:0]   Op2
pub fn packSysreg(op0: u2, op1: u3, crn: u4, crm: u4, op2: u3) u16 {
    return (@as(u16, op0) << 14) |
        (@as(u16, op1) << 11) |
        (@as(u16, crn) << 7) |
        (@as(u16, crm) << 3) |
        @as(u16, op2);
}

/// Convenience wrapper used by the policy lookups below.
pub fn packSysregTrap(trap: vm_hw.VmExitInfo.SysregTrap) u16 {
    return packSysreg(trap.op0, trap.op1, trap.crn, trap.crm, trap.op2);
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

/// Inject an undefined-instruction exception at the guest's current PC.
/// Used for HVC with a non-zero imm16 — Zag defines no hypercalls today,
/// so the guest sees the call as if the HVC instruction itself were
/// undefined at EL1 (ARM ARM D1.11, vector offset 0x400 for a lower-EL
/// AArch64 synchronous exception).
fn injectUndef(vcpu_obj: *VCpu) void {
    // ESR_EL1.EC = 0x00 (unknown reason), IL = 1 (32-bit instruction).
    const esr: u64 = (@as(u64, 0x00) << 26) | (1 << 25);
    vm_hw.injectException(&vcpu_obj.guest_state, .{
        .esr = esr,
        .far = 0,
        .vector_slot = 4, // lower EL (aarch64) sync
    });
}
