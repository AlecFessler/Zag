const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;
const Process = zag.proc.process.Process;
const SyscallResult = zag.syscall.dispatch.SyscallResult;
const Thread = zag.sched.thread.Thread;
const Vm = zag.arch.dispatch.vm.Vm;
const VCpu = zag.arch.dispatch.vm.VCpu;

// --- KVM syscall dispatch ---
// These dispatch the syscall-facing KVM operations through the arch boundary.
// x86 backend lives in arch/x64/kvm/, aarch64 backend in arch/aarch64/kvm/.
// The syscall layer calls through this abstraction and never references the
// per-arch modules directly.

pub fn kvmVmCreate(proc: *Process, vcpu_count: u32, policy_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.vmCreate(proc, vcpu_count, policy_ptr),
        .aarch64 => aarch64.kvm.vm.vmCreate(proc, vcpu_count, policy_ptr),
        else => -14, // E_NOSYS
    };
}

pub fn kvmGuestMap(proc: *Process, vm_handle: u64, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.guestMap(proc, vm_handle, host_vaddr, guest_addr, size, rights),
        .aarch64 => aarch64.kvm.vm.guestMap(proc, vm_handle, host_vaddr, guest_addr, size, rights),
        else => -14,
    };
}

pub fn kvmVmRecv(proc: *Process, thread: *Thread, ctx: *ArchCpuContext, vm_handle: u64, buf_ptr: u64, blocking: bool) SyscallResult {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.exit_box.vmRecv(proc, thread, ctx, vm_handle, buf_ptr, blocking),
        .aarch64 => .{ .ret = aarch64.kvm.exit_box.vmRecv(proc, thread, ctx, vm_handle, buf_ptr, blocking) },
        else => .{ .ret = -14 },
    };
}

pub fn kvmVmReply(proc: *Process, vm_handle: u64, exit_token: u64, action_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.exit_box.vmReply(proc, vm_handle, exit_token, action_ptr),
        .aarch64 => aarch64.kvm.exit_box.vmReply(proc, vm_handle, exit_token, action_ptr),
        else => -14,
    };
}

pub fn kvmVcpuSetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuSetState(proc, thread_handle, state_ptr),
        .aarch64 => aarch64.kvm.vcpu.vcpuSetState(proc, thread_handle, state_ptr),
        else => -14,
    };
}

pub fn kvmVcpuGetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuGetState(proc, thread_handle, state_ptr),
        .aarch64 => aarch64.kvm.vcpu.vcpuGetState(proc, thread_handle, state_ptr),
        else => -14,
    };
}

pub fn kvmVcpuRun(proc: *Process, thread_handle: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuRun(proc, thread_handle),
        .aarch64 => aarch64.kvm.vcpu.vcpuRun(proc, thread_handle),
        else => -14,
    };
}

pub fn kvmVcpuInterrupt(proc: *Process, thread_handle: u64, interrupt_ptr: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuInterrupt(proc, thread_handle, interrupt_ptr),
        .aarch64 => aarch64.kvm.vcpu.vcpuInterrupt(proc, thread_handle, interrupt_ptr),
        else => -14,
    };
}

pub fn kvmSysregPassthrough(proc: *Process, vm_handle: u64, sysreg_id: u32, allow_read: bool, allow_write: bool) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.sysregPassthrough(proc, vm_handle, sysreg_id, allow_read, allow_write),
        .aarch64 => aarch64.kvm.vm.sysregPassthrough(proc, vm_handle, sysreg_id, allow_read, allow_write),
        else => -14,
    };
}

pub fn kvmIntcAssertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.intcAssertIrq(proc, vm_handle, irq_num),
        .aarch64 => aarch64.kvm.vm.intcAssertIrq(proc, vm_handle, irq_num),
        else => -14,
    };
}

pub fn kvmIntcDeassertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.intcDeassertIrq(proc, vm_handle, irq_num),
        .aarch64 => aarch64.kvm.vm.intcDeassertIrq(proc, vm_handle, irq_num),
        else => -14,
    };
}

pub fn kvmVcpuFromThread(vm_obj: *Vm, thread: *Thread) ?*VCpu {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.vcpuFromThread(vm_obj, thread),
        .aarch64 => aarch64.kvm.vcpu.vcpuFromThread(vm_obj, thread),
        else => null,
    };
}

pub fn kvmSetVmAllocator(alloc: std.mem.Allocator) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.allocator = alloc,
        .aarch64 => aarch64.kvm.vm.allocator = alloc,
        else => {},
    }
}

pub fn kvmSetVcpuAllocator(alloc: std.mem.Allocator) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.allocator = alloc,
        .aarch64 => aarch64.kvm.vcpu.allocator = alloc,
        else => {},
    }
}
