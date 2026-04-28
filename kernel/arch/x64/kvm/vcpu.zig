const zag = @import("zag");

const vm_hw = zag.arch.x64.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;

// ── Spec-v3 dispatch backings ────────────────────────────────────────
//
// Wire-up scope: allocate a per-vCPU arch state cell from PMM and pin
// it on the EC. Run-time bring-up (loadGuestState/saveGuestState/
// enterGuest/lastVmExitInfo) follows once the vCPU run loop is wired.

pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    if (!vm_hw.vmSupported()) return error.NoDevice;
    _ = vm;
    _ = vcpu_ec;
}
