//! Aarch64 VCpu dispatch backing stubs.
//!
//! Per-vCPU arch state, world-switch entry/exit, and VM-exit delivery
//! all flow through these dispatch primitives once the spec-v3 vCPU
//! run loop is wired up. For now they're @panic placeholders.

const zag = @import("zag");

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const VmExitInfo = zag.arch.dispatch.vm.VmExitInfo;

pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    _ = vm;
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn loadGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn saveGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn enterGuest(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn lastVmExitInfo(vcpu_ec: *ExecutionContext) VmExitInfo {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}
