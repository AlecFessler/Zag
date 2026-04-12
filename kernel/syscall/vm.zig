const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const sched = zag.sched.scheduler;

const ArchCpuContext = arch.ArchCpuContext;
const SyscallResult = zag.syscall.dispatch.SyscallResult;

const E_INVAL = errors.E_INVAL;

pub fn sysVmCreate(vcpu_count: u64, policy_ptr: u64) i64 {
    const proc = sched.currentProc();
    if (vcpu_count > std.math.maxInt(u32)) return E_INVAL;
    return arch.kvmVmCreate(proc, @intCast(vcpu_count), policy_ptr);
}

pub fn sysVmGuestMap(vm_handle: u64, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    const proc = sched.currentProc();
    return arch.kvmGuestMap(proc, vm_handle, host_vaddr, guest_addr, size, rights);
}

pub fn sysVmRecv(ctx: *ArchCpuContext, vm_handle: u64, buf_ptr: u64, blocking: u64) SyscallResult {
    const thread = sched.currentThread().?;
    const proc = thread.process;
    return arch.kvmVmRecv(proc, thread, ctx, vm_handle, buf_ptr, blocking != 0);
}

pub fn sysVmReplyCall(vm_handle: u64, exit_token: u64, action_ptr: u64) i64 {
    const proc = sched.currentProc();
    return arch.kvmVmReply(proc, vm_handle, exit_token, action_ptr);
}

pub fn sysVmVcpuSetState(thread_handle: u64, state_ptr: u64) i64 {
    const proc = sched.currentProc();
    return arch.kvmVcpuSetState(proc, thread_handle, state_ptr);
}

pub fn sysVmVcpuGetState(thread_handle: u64, state_ptr: u64) i64 {
    const proc = sched.currentProc();
    return arch.kvmVcpuGetState(proc, thread_handle, state_ptr);
}

pub fn sysVmVcpuRun(thread_handle: u64) i64 {
    const proc = sched.currentProc();
    return arch.kvmVcpuRun(proc, thread_handle);
}

pub fn sysVmVcpuInterrupt(thread_handle: u64, interrupt_ptr: u64) i64 {
    const proc = sched.currentProc();
    return arch.kvmVcpuInterrupt(proc, thread_handle, interrupt_ptr);
}

pub fn sysVmMsrPassthrough(vm_handle: u64, msr_num: u64, allow_read: u64, allow_write: u64) i64 {
    const proc = sched.currentProc();
    if (msr_num > std.math.maxInt(u32)) return E_INVAL;
    return arch.kvmMsrPassthrough(proc, vm_handle, @truncate(msr_num), allow_read != 0, allow_write != 0);
}

pub fn sysVmIoapicAssertIrq(vm_handle: u64, irq_num: u64) i64 {
    const proc = sched.currentProc();
    return arch.kvmIoapicAssertIrq(proc, vm_handle, irq_num);
}

pub fn sysVmIoapicDeassertIrq(vm_handle: u64, irq_num: u64) i64 {
    const proc = sched.currentProc();
    return arch.kvmIoapicDeassertIrq(proc, vm_handle, irq_num);
}
