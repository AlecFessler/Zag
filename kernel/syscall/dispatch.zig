const zag = @import("zag");

const clock = zag.syscall.clock;
const device = zag.syscall.device;
const errors = zag.syscall.errors;
const fault = zag.syscall.fault;
const futex = zag.syscall.futex;
const ipc = zag.syscall.ipc;
const memory = zag.syscall.memory;
const pmu = zag.syscall.pmu;
const process = zag.syscall.process;
const sysinfo = zag.syscall.sysinfo;
const system = zag.syscall.system;
const thread = zag.syscall.thread;
const vm = zag.syscall.vm;

const ArchCpuContext = zag.arch.dispatch.ArchCpuContext;

const E_INVAL = errors.E_INVAL;

pub const SyscallResult = struct {
    rax: i64,
    rdx: u64 = 0,
};

pub const SyscallNum = enum(u64) {
    write,
    mem_reserve,
    mem_perms,
    mem_shm_create,
    mem_shm_map,
    mem_shm_unmap,
    mem_mmio_map,
    mem_mmio_unmap,
    proc_create,
    thread_create,
    thread_exit,
    thread_yield,
    set_affinity,
    revoke_perm,
    disable_restart,
    futex_wait,
    futex_wake,
    clock_gettime,
    ioport_read,
    ioport_write,
    mem_dma_map,
    mem_dma_unmap,
    set_priority,
    ipc_send,
    ipc_call,
    ipc_recv,
    ipc_reply,
    shutdown,
    thread_self,
    thread_suspend,
    thread_resume,
    thread_kill,
    fault_recv,
    fault_reply,
    fault_read_mem,
    fault_write_mem,
    fault_set_thread_mode,
    vm_create,
    vm_destroy,
    vm_guest_map,
    vm_recv,
    vm_reply,
    vm_vcpu_set_state,
    vm_vcpu_get_state,
    vm_vcpu_run,
    vm_vcpu_interrupt,
    vm_msr_passthrough,
    vm_ioapic_assert_irq,
    vm_ioapic_deassert_irq,
    pmu_info,
    pmu_start,
    pmu_read,
    pmu_reset,
    pmu_stop,
    sys_info,
    clock_getwall,
    clock_setwall,
    getrandom,
    notify_wait,
    irq_ack,
    sys_power,
    sys_cpu_power,
    _,
};

pub fn dispatch(ctx: *ArchCpuContext) SyscallResult {
    const num = ctx.regs.rax;
    const arg0 = ctx.regs.rdi;
    const arg1 = ctx.regs.rsi;
    const arg2 = ctx.regs.rdx;
    const arg3 = ctx.regs.r10;
    const arg4 = ctx.regs.r8;
    const syscall_num: SyscallNum = @enumFromInt(num);
    return switch (syscall_num) {
        .write => system.sysWrite(arg0, arg1),
        .mem_reserve => memory.sysMemReserve(arg0, arg1, arg2),
        .mem_perms => .{ .rax = memory.sysMemPerms(arg0, arg1, arg2, arg3) },
        .mem_shm_create => .{ .rax = memory.sysMemShmCreate(arg0, arg1) },
        .mem_shm_map => .{ .rax = memory.sysMemShmMap(arg0, arg1, arg2) },
        .mem_shm_unmap => .{ .rax = memory.sysMemShmUnmap(arg0, arg1) },
        .mem_mmio_map => .{ .rax = device.sysMemMmioMap(arg0, arg1, arg2) },
        .mem_mmio_unmap => .{ .rax = device.sysMemMmioUnmap(arg0, arg1) },
        .proc_create => .{ .rax = process.sysProcCreate(arg0, arg1, arg2, arg3, arg4) },
        .thread_create => .{ .rax = thread.sysThreadCreate(arg0, arg1, arg2) },
        .thread_exit => thread.sysThreadExit(),
        .thread_yield => .{ .rax = thread.sysThreadYield() },
        .set_affinity => .{ .rax = thread.sysSetAffinity(arg0) },
        .revoke_perm => .{ .rax = process.sysRevokePerm(arg0) },
        .disable_restart => .{ .rax = process.sysDisableRestart() },
        .futex_wait => .{ .rax = futex.sysFutexWait(arg0, arg1, arg2) },
        .futex_wake => .{ .rax = futex.sysFutexWake(arg0, arg1) },
        .clock_gettime => .{ .rax = clock.sysClockGettime() },
        .ioport_read => .{ .rax = device.sysIoportRead(arg0, arg1, arg2) },
        .ioport_write => .{ .rax = device.sysIoportWrite(arg0, arg1, arg2, arg3) },
        .mem_dma_map => .{ .rax = device.sysMemDmaMap(arg0, arg1) },
        .mem_dma_unmap => .{ .rax = device.sysMemDmaUnmap(arg0, arg1) },
        .set_priority => .{ .rax = thread.sysSetPriority(arg0) },
        .ipc_send => ipc.sysIpcSend(ctx),
        .ipc_call => ipc.sysIpcCall(ctx),
        .ipc_recv => ipc.sysIpcRecv(ctx),
        .ipc_reply => ipc.sysIpcReply(ctx),
        .shutdown => .{ .rax = system.sysSysPower(0) },
        .thread_self => .{ .rax = thread.sysThreadSelf() },
        .thread_suspend => .{ .rax = thread.sysThreadSuspend(arg0) },
        .thread_resume => .{ .rax = thread.sysThreadResume(arg0) },
        .thread_kill => .{ .rax = thread.sysThreadKill(arg0) },
        .fault_recv => fault.sysFaultRecv(ctx, arg0, arg1),
        .fault_reply => .{ .rax = fault.sysFaultReply(ctx, arg0, arg1, arg2) },
        .fault_read_mem => .{ .rax = fault.sysFaultReadMem(arg0, arg1, arg2, arg3) },
        .fault_write_mem => .{ .rax = fault.sysFaultWriteMem(arg0, arg1, arg2, arg3) },
        .fault_set_thread_mode => .{ .rax = fault.sysFaultSetThreadMode(arg0, arg1) },
        .vm_create => .{ .rax = vm.sysVmCreate(arg0, arg1) },
        .vm_destroy => .{ .rax = E_INVAL },
        .vm_guest_map => .{ .rax = vm.sysVmGuestMap(arg0, arg1, arg2, arg3, arg4) },
        .vm_recv => vm.sysVmRecv(ctx, arg0, arg1, arg2),
        .vm_reply => .{ .rax = vm.sysVmReplyCall(arg0, arg1, arg2) },
        .vm_vcpu_set_state => .{ .rax = vm.sysVmVcpuSetState(arg0, arg1) },
        .vm_vcpu_get_state => .{ .rax = vm.sysVmVcpuGetState(arg0, arg1) },
        .vm_vcpu_run => .{ .rax = vm.sysVmVcpuRun(arg0) },
        .vm_vcpu_interrupt => .{ .rax = vm.sysVmVcpuInterrupt(arg0, arg1) },
        .vm_msr_passthrough => .{ .rax = vm.sysVmMsrPassthrough(arg0, arg1, arg2, arg3) },
        .vm_ioapic_assert_irq => .{ .rax = vm.sysVmIoapicAssertIrq(arg0, arg1) },
        .vm_ioapic_deassert_irq => .{ .rax = vm.sysVmIoapicDeassertIrq(arg0, arg1) },
        .pmu_info => .{ .rax = pmu.sysPmuInfo(zag.sched.scheduler.currentProc(), arg0) },
        .pmu_start => .{ .rax = pmu.sysPmuStart(zag.sched.scheduler.currentProc(), arg0, arg1, arg2) },
        .pmu_read => .{ .rax = pmu.sysPmuRead(zag.sched.scheduler.currentProc(), arg0, arg1) },
        .pmu_reset => .{ .rax = pmu.sysPmuReset(zag.sched.scheduler.currentProc(), arg0, arg1, arg2) },
        .pmu_stop => .{ .rax = pmu.sysPmuStop(zag.sched.scheduler.currentProc(), arg0) },
        .sys_info => .{ .rax = sysinfo.sysSysInfo(zag.sched.scheduler.currentProc(), arg0, arg1) },
        .clock_getwall => .{ .rax = clock.sysClockGetwall() },
        .clock_setwall => .{ .rax = clock.sysClockSetwall(arg0) },
        .getrandom => .{ .rax = system.sysGetrandom(arg0, arg1) },
        .notify_wait => .{ .rax = system.sysNotifyWait(arg0) },
        .irq_ack => .{ .rax = device.sysIrqAck(arg0) },
        .sys_power => .{ .rax = system.sysSysPower(arg0) },
        .sys_cpu_power => .{ .rax = system.sysSysCpuPower(arg0, arg1) },
        _ => .{ .rax = E_INVAL },
    };
}
