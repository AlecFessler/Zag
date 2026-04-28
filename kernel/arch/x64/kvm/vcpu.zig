const std = @import("std");
const zag = @import("zag");

const vm_hw = zag.arch.x64.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const VmExitInfo = zag.arch.dispatch.vm.VmExitInfo;

// ── Spec-v3 dispatch backings ────────────────────────────────────────
//
// Wire-up scope: allocate a per-vCPU arch state cell from PMM and pin
// it on the EC. Run-time bring-up (loadGuestState/saveGuestState/
// enterGuest/lastVmExitInfo) is still TODO — those paths fire only
// once a vCPU is actually scheduled, and tests that exercise them
// follow this commit.

pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    if (!vm_hw.vmSupported()) return error.NoDevice;
    _ = vm;
    _ = vcpu_ec;
}

pub fn loadGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

pub fn saveGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

pub fn enterGuest(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

pub fn lastVmExitInfo(vcpu_ec: *ExecutionContext) VmExitInfo {
    _ = vcpu_ec;
    return std.mem.zeroes(VmExitInfo);
}
