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
    ret: i64,
    ret2: u64 = 0,
};

pub const SyscallNum = enum(u64) {
    write,
    mem_reserve,
    mem_perms,
    mem_shm_create,
    mem_shm_map,
    mem_unmap,
    mem_mmio_map,
    _mem_mmio_unmap_removed,
    proc_create,
    thread_create,
    thread_exit,
    thread_yield,
    set_affinity,
    revoke_perm,
    disable_restart,
    futex_wait_val,
    futex_wake,
    clock_gettime,
    _ioport_read_removed,
    _ioport_write_removed,
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
    _notify_wait_removed,
    irq_ack,
    sys_power,
    sys_cpu_power,
    _thread_unpin_removed,
    futex_wait_change,
    _,
};

pub fn dispatch(ctx: *ArchCpuContext) SyscallResult {
    const args = zag.arch.dispatch.getSyscallArgs(ctx);
    const arg0 = args.arg0;
    const arg1 = args.arg1;
    const arg2 = args.arg2;
    const arg3 = args.arg3;
    const arg4 = args.arg4;
    const syscall_num: SyscallNum = @enumFromInt(args.num);
    return switch (syscall_num) {
        .write => system.sysWrite(arg0, arg1),
        .mem_reserve => memory.sysMemReserve(arg0, arg1, arg2),
        .mem_perms => .{ .ret = memory.sysMemPerms(arg0, arg1, arg2, arg3) },
        .mem_shm_create => .{ .ret = memory.sysMemShmCreate(arg0, arg1) },
        .mem_shm_map => .{ .ret = memory.sysMemShmMap(arg0, arg1, arg2) },
        .mem_unmap => .{ .ret = memory.sysMemUnmap(arg0, arg1, arg2) },
        .mem_mmio_map => .{ .ret = device.sysMemMmioMap(arg0, arg1, arg2) },
        ._mem_mmio_unmap_removed => .{ .ret = E_INVAL },
        .proc_create => .{ .ret = process.sysProcCreate(arg0, arg1, arg2, arg3, arg4) },
        .thread_create => .{ .ret = thread.sysThreadCreate(arg0, arg1, arg2) },
        .thread_exit => thread.sysThreadExit(),
        .thread_yield => .{ .ret = thread.sysThreadYield() },
        .set_affinity => .{ .ret = thread.sysSetAffinity(arg0) },
        .revoke_perm => .{ .ret = process.sysRevokePerm(arg0) },
        .disable_restart => .{ .ret = process.sysDisableRestart() },
        .futex_wait_val => .{ .ret = futex.sysFutexWaitVal(arg0, arg1, arg2, arg3) },
        .futex_wake => .{ .ret = futex.sysFutexWake(arg0, arg1) },
        .clock_gettime => .{ .ret = clock.sysClockGettime() },
        ._ioport_read_removed => .{ .ret = E_INVAL },
        ._ioport_write_removed => .{ .ret = E_INVAL },
        .mem_dma_map => .{ .ret = device.sysMemDmaMap(arg0, arg1) },
        .mem_dma_unmap => .{ .ret = device.sysMemDmaUnmap(arg0, arg1) },
        .set_priority => .{ .ret = thread.sysSetPriority(arg0) },
        .ipc_send => ipc.sysIpcSend(ctx),
        .ipc_call => ipc.sysIpcCall(ctx),
        .ipc_recv => ipc.sysIpcRecv(ctx),
        .ipc_reply => ipc.sysIpcReply(ctx),
        .shutdown => .{ .ret = system.sysSysPower(0) },
        .thread_self => .{ .ret = thread.sysThreadSelf() },
        .thread_suspend => .{ .ret = thread.sysThreadSuspend(arg0) },
        .thread_resume => .{ .ret = thread.sysThreadResume(arg0) },
        .thread_kill => .{ .ret = thread.sysThreadKill(arg0) },
        .fault_recv => fault.sysFaultRecv(ctx, arg0, arg1),
        .fault_reply => .{ .ret = fault.sysFaultReply(ctx, arg0, arg1, arg2) },
        .fault_read_mem => .{ .ret = fault.sysFaultReadMem(arg0, arg1, arg2, arg3) },
        .fault_write_mem => .{ .ret = fault.sysFaultWriteMem(arg0, arg1, arg2, arg3) },
        .fault_set_thread_mode => .{ .ret = fault.sysFaultSetThreadMode(arg0, arg1) },
        .vm_create => .{ .ret = vm.sysVmCreate(arg0, arg1) },
        .vm_destroy => .{ .ret = E_INVAL },
        .vm_guest_map => .{ .ret = vm.sysVmGuestMap(arg0, arg1, arg2, arg3, arg4) },
        .vm_recv => vm.sysVmRecv(ctx, arg0, arg1, arg2),
        .vm_reply => .{ .ret = vm.sysVmReplyCall(arg0, arg1, arg2) },
        .vm_vcpu_set_state => .{ .ret = vm.sysVmVcpuSetState(arg0, arg1) },
        .vm_vcpu_get_state => .{ .ret = vm.sysVmVcpuGetState(arg0, arg1) },
        .vm_vcpu_run => .{ .ret = vm.sysVmVcpuRun(arg0) },
        .vm_vcpu_interrupt => .{ .ret = vm.sysVmVcpuInterrupt(arg0, arg1) },
        .vm_msr_passthrough => .{ .ret = vm.sysVmMsrPassthrough(arg0, arg1, arg2, arg3) },
        .vm_ioapic_assert_irq => .{ .ret = vm.sysVmIoapicAssertIrq(arg0, arg1) },
        .vm_ioapic_deassert_irq => .{ .ret = vm.sysVmIoapicDeassertIrq(arg0, arg1) },
        .pmu_info => .{ .ret = pmu.sysPmuInfo(zag.sched.scheduler.currentProc(), arg0) },
        .pmu_start => .{ .ret = pmu.sysPmuStart(zag.sched.scheduler.currentProc(), arg0, arg1, arg2) },
        .pmu_read => .{ .ret = pmu.sysPmuRead(zag.sched.scheduler.currentProc(), arg0, arg1) },
        .pmu_reset => .{ .ret = pmu.sysPmuReset(zag.sched.scheduler.currentProc(), arg0, arg1, arg2) },
        .pmu_stop => .{ .ret = pmu.sysPmuStop(zag.sched.scheduler.currentProc(), arg0) },
        .sys_info => .{ .ret = sysinfo.sysSysInfo(zag.sched.scheduler.currentProc(), arg0, arg1) },
        .clock_getwall => .{ .ret = clock.sysClockGetwall() },
        .clock_setwall => .{ .ret = clock.sysClockSetwall(arg0) },
        .getrandom => .{ .ret = system.sysGetrandom(arg0, arg1) },
        ._notify_wait_removed => .{ .ret = E_INVAL },
        .irq_ack => .{ .ret = device.sysIrqAck(arg0) },
        .sys_power => .{ .ret = system.sysSysPower(arg0) },
        .sys_cpu_power => .{ .ret = system.sysSysCpuPower(arg0, arg1) },
        ._thread_unpin_removed => .{ .ret = E_INVAL },
        .futex_wait_change => .{ .ret = futex.sysFutexWaitChange(arg0, arg1, arg2) },
        _ => .{ .ret = E_INVAL },
    };
}
