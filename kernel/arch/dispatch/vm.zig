const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;
const Process = zag.proc.process.Process;
const SyscallResult = zag.syscall.dispatch.SyscallResult;
const Thread = zag.sched.thread.Thread;

// Generic-kernel-facing VM dispatch. Arch-internal primitives (guest-page
// mapping, interrupt injection, world-switch, sysreg passthrough, etc.)
// are reached directly by the per-arch VMM code — they don't belong in
// dispatch because no generic-kernel callers need them. This module
// exposes only what the scheduler, process layer, and syscall layer use.

// --- Opaque types referenced by generic kernel --------------------------

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

// --- Init ---------------------------------------------------------------

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
        .aarch64 => {
            aarch64.vm.vmPerCoreInit();
            // EL2 vector-table install is a per-core concern but lives in
            // the hyp.zig half of the aarch64 VM split; keep the call-out
            // here so vm.zig does not need a back-reference into hyp.
            aarch64.hyp.installHypVectors();
        },
        else => unreachable,
    }
}

/// BSP post-bootloader handoff. On aarch64, when UEFI's firmware drops
/// us at EL2 (only observable by the bootloader, which signals via
/// `boot_info.arrived_at_el2`), arm the hyp-stub gate and install the
/// kernel's EL2 vector table — must run before secondaries start since
/// only the BSP inherits the bootloader's EL2 vector stub. No-op on x86.
pub fn bspBootHandoff(arrived_at_el2: bool) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => if (arrived_at_el2) {
            aarch64.vm.hyp_stub_installed = true;
            aarch64.hyp.installHypVectors();
        },
        else => unreachable,
    }
}

pub fn setVmAllocator(alloc: std.mem.Allocator) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.allocator = alloc,
        .aarch64 => aarch64.kvm.vm.allocator = alloc,
        else => {},
    }
}

pub fn setVcpuAllocator(alloc: std.mem.Allocator) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.allocator = alloc,
        .aarch64 => aarch64.kvm.vcpu.allocator = alloc,
        else => {},
    }
}

// --- Syscall entry points ----------------------------------------------

pub fn vmCreate(proc: *Process, vcpu_count: u32, policy_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.vmCreate(proc, vcpu_count, policy_ptr),
        .aarch64 => aarch64.kvm.vm.vmCreate(proc, vcpu_count, policy_ptr),
        else => -14, // E_NOSYS
    };
}

pub fn guestMap(proc: *Process, vm_handle: u64, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.guestMap(proc, vm_handle, host_vaddr, guest_addr, size, rights),
        .aarch64 => aarch64.kvm.vm.guestMap(proc, vm_handle, host_vaddr, guest_addr, size, rights),
        else => -14,
    };
}

pub fn vmRecv(proc: *Process, thread: *Thread, ctx: *ArchCpuContext, vm_handle: u64, buf_ptr: u64, blocking: bool) SyscallResult {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.exit_box.vmRecv(proc, thread, ctx, vm_handle, buf_ptr, blocking),
        .aarch64 => .{ .ret = aarch64.kvm.exit_box.vmRecv(proc, thread, ctx, vm_handle, buf_ptr, blocking) },
        else => .{ .ret = -14 },
    };
}

pub fn vmReply(proc: *Process, vm_handle: u64, exit_token: u64, action_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.exit_box.vmReply(proc, vm_handle, exit_token, action_ptr),
        .aarch64 => aarch64.kvm.exit_box.vmReply(proc, vm_handle, exit_token, action_ptr),
        else => -14,
    };
}

pub fn vcpuSetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuSetState(proc, thread_handle, state_ptr),
        .aarch64 => aarch64.kvm.vcpu.vcpuSetState(proc, thread_handle, state_ptr),
        else => -14,
    };
}

pub fn vcpuGetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuGetState(proc, thread_handle, state_ptr),
        .aarch64 => aarch64.kvm.vcpu.vcpuGetState(proc, thread_handle, state_ptr),
        else => -14,
    };
}

pub fn vcpuRun(proc: *Process, thread_handle: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuRun(proc, thread_handle),
        .aarch64 => aarch64.kvm.vcpu.vcpuRun(proc, thread_handle),
        else => -14,
    };
}

pub fn vcpuInterrupt(proc: *Process, thread_handle: u64, interrupt_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuInterrupt(proc, thread_handle, interrupt_ptr),
        .aarch64 => aarch64.kvm.vcpu.vcpuInterrupt(proc, thread_handle, interrupt_ptr),
        else => -14,
    };
}

pub fn sysregPassthrough(proc: *Process, vm_handle: u64, sysreg_id: u32, allow_read: bool, allow_write: bool) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.sysregPassthrough(proc, vm_handle, sysreg_id, allow_read, allow_write),
        .aarch64 => aarch64.kvm.vm.sysregPassthrough(proc, vm_handle, sysreg_id, allow_read, allow_write),
        else => -14,
    };
}

pub fn intcAssertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.intcAssertIrq(proc, vm_handle, irq_num),
        .aarch64 => aarch64.kvm.vm.intcAssertIrq(proc, vm_handle, irq_num),
        else => -14,
    };
}

pub fn intcDeassertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.intcDeassertIrq(proc, vm_handle, irq_num),
        .aarch64 => aarch64.kvm.vm.intcDeassertIrq(proc, vm_handle, irq_num),
        else => -14,
    };
}

/// Whether `thread` is a vCPU owned by `vm_obj`. Used by the process exit
/// path to detect "only vCPU threads remain" and tear the VM down.
pub fn threadIsVcpu(vm_obj: *Vm, thread: *Thread) bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuFromThread(vm_obj, thread) != null,
        .aarch64 => aarch64.kvm.vcpu.vcpuFromThread(vm_obj, thread) != null,
        else => false,
    };
}
