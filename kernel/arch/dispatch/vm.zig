const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const PAddr = zag.memory.address.PAddr;

// --- VM (hardware virtualization) dispatch ---

// --- KVM types dispatched from arch/x64/kvm/ ---

pub const Vm = switch (builtin.cpu.arch) {
    .x86_64 => x64.kvm.vm.Vm,
    .aarch64 => aarch64.kvm.vm.Vm,
    else => @compileError("unsupported arch for VM"),
};

pub const VmAllocator = switch (builtin.cpu.arch) {
    .x86_64 => x64.kvm.vm.VmAllocator,
    .aarch64 => aarch64.kvm.vm.VmAllocator,
    else => @compileError("unsupported arch for VM"),
};

pub const VCpuAllocator = switch (builtin.cpu.arch) {
    .x86_64 => x64.kvm.vcpu.VCpuAllocator,
    .aarch64 => aarch64.kvm.vcpu.VCpuAllocator,
    else => @compileError("unsupported arch for VM"),
};

pub const GuestState = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.GuestState,
    .aarch64 => aarch64.vm.GuestState,
    else => @compileError("unsupported arch for VM"),
};

pub const VmExitInfo = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.VmExitInfo,
    .aarch64 => aarch64.vm.VmExitInfo,
    else => @compileError("unsupported arch for VM"),
};

pub const GuestInterrupt = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.GuestInterrupt,
    .aarch64 => aarch64.vm.GuestInterrupt,
    else => @compileError("unsupported arch for VM"),
};

pub const GuestException = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.GuestException,
    .aarch64 => aarch64.vm.GuestException,
    else => @compileError("unsupported arch for VM"),
};

pub const VmPolicy = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.VmPolicy,
    .aarch64 => aarch64.vm.VmPolicy,
    else => @compileError("unsupported arch for VM"),
};

pub const FxsaveArea = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm.FxsaveArea,
    .aarch64 => aarch64.vm.FxsaveArea,
    else => @compileError("unsupported arch for VM"),
};

/// Per-arch concrete VCpu type (used by the syscall layer to type-check
/// the result of kvmVcpuFromThread without going through dispatch.Vm).
pub const VCpu = switch (builtin.cpu.arch) {
    .x86_64 => x64.kvm.vcpu.VCpu,
    .aarch64 => aarch64.kvm.vcpu.VCpu,
    else => @compileError("unsupported arch for VM"),
};

pub fn fxsaveInit() FxsaveArea {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.fxsaveInit(),
        .aarch64 => aarch64.vm.fxsaveInit(),
        else => @compileError("unsupported arch for VM"),
    };
}

pub fn vmInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmInit(),
        .aarch64 => aarch64.vm.vmInit(),
        else => unreachable,
    }
}

pub fn vmPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmPerCoreInit(),
        .aarch64 => aarch64.vm.vmPerCoreInit(),
        else => unreachable,
    }
}

pub fn vmSupported() bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmSupported(),
        .aarch64 => aarch64.vm.vmSupported(),
        else => unreachable,
    };
}

// Note: there is no `arch.vm.vmResume` at the dispatch layer. Guest entry
// is inherently per-arch — x86 needs only (guest_state, vm_structures,
// guest_fxsave), while aarch64 additionally threads a per-vCPU
// `arch_scratch` through (for the EL2 world-switch marshalling block).
// Both architectures' KVM vcpu loops call their own `vm_hw.vmResume`
// directly. A dispatch fn here would either have to carry the extra
// arg on both sides (dead weight for x86) or silently ignore it
// (back-door divergence), so it is intentionally absent.

pub fn vmAllocStructures() ?PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmAllocStructures(),
        .aarch64 => aarch64.vm.vmAllocStructures(),
        else => unreachable,
    };
}

pub fn vmFreeStructures(paddr: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmFreeStructures(paddr),
        .aarch64 => aarch64.vm.vmFreeStructures(paddr),
        else => unreachable,
    }
}

pub fn mapGuestPage(vm_structures: PAddr, guest_phys: u64, host_phys: PAddr, rights: u8) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.vm.mapGuestPage(vm_structures, guest_phys, host_phys, rights),
        .aarch64 => try aarch64.vm.mapGuestPage(vm_structures, guest_phys, host_phys, rights),
        else => unreachable,
    }
}

pub fn unmapGuestPage(vm_structures: PAddr, guest_phys: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.unmapGuestPage(vm_structures, guest_phys),
        .aarch64 => aarch64.vm.unmapGuestPage(vm_structures, guest_phys),
        else => unreachable,
    }
}

pub fn vmInjectInterrupt(guest_state: *GuestState, interrupt: GuestInterrupt) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.injectInterrupt(guest_state, interrupt),
        .aarch64 => aarch64.kvm.vcpu.injectInterrupt(guest_state, interrupt),
        else => unreachable,
    }
}

pub fn vmInjectException(guest_state: *GuestState, exception: GuestException) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.injectException(guest_state, exception),
        .aarch64 => aarch64.vm.injectException(guest_state, exception),
        else => unreachable,
    }
}

/// Modify system-register passthrough bits in the VM's per-sysreg trap map.
/// On AMD SVM: AMD APM Vol 2, §15.10 "MSR Intercepts" — the MSRPM is an 8-KB
/// bitmap; two bits per MSR (bit 0 = read intercept, bit 1 = write intercept);
/// 0 = passthrough, 1 = intercept. MSRs 0x0000–0x1FFF at byte offset 0x000;
/// MSRs 0xC0000000–0xC0001FFF at byte offset 0x800.
/// On Intel VMX: Intel SDM Vol 3C, §24.6.9 "MSR-Bitmap Address" — a 4-KB
/// bitmap with four 1-KB regions for RDMSR/WRMSR on low/high MSR ranges.
/// On ARMv8: HCR_EL2/CPTR_EL2/MDCR_EL2/CNTHCTL_EL2 trap bits per register class
/// (ARM ARM D13) — `sysreg_id` is a packed (op0,op1,CRn,CRm,op2) encoding.
pub fn vmSysregPassthrough(vm_structures: PAddr, sysreg_id: u32, allow_read: bool, allow_write: bool) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.sysregPassthrough(vm_structures, sysreg_id, allow_read, allow_write),
        .aarch64 => aarch64.vm.sysregPassthrough(vm_structures, sysreg_id, allow_read, allow_write),
        else => unreachable,
    }
}
