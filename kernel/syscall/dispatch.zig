//! Spec-v3 syscall dispatch table — switches on the syscall number
//! encoded in the syscall word and trampolines into the per-object
//! handler in this directory. The arch-specific entry path collects
//! register-passed args and any vreg-passed extras into the `args`
//! slice before calling here. See docs/kernel/specv3.md §[syscall].
//!
//! `caller` is the calling EC, type-erased to keep the syscall surface
//! free of the per-arch context type. Each handler casts it back to
//! `*ExecutionContext` internally.

const std = @import("std");
const zag = @import("zag");

const capability = zag.syscall.capability;
const capability_domain = zag.syscall.capability_domain;
const errors = zag.syscall.errors;
const event_route = zag.syscall.event_route;
const execution_context = zag.syscall.execution_context;
const futex = zag.syscall.futex;
const page_frame = zag.syscall.page_frame;
const port = zag.syscall.port;
const reply = zag.syscall.reply;
const system = zag.syscall.system;
const timer = zag.syscall.timer;
const var_ = zag.syscall.var_;
const virtual_machine = zag.syscall.virtual_machine;

pub const SyscallNum = enum(u64) {
    ack = 26,
    acquire_ecs = 5,
    acquire_vars = 6,
    affinity = 12,
    bind_event_route = 36,
    clear_event_route = 37,
    create_capability_domain = 4,
    create_execution_context = 7,
    create_page_frame = 25,
    create_port = 33,
    create_var = 17,
    create_vcpu = 28,
    create_virtual_machine = 27,
    delete = 1,
    futex_wait_change = 44,
    futex_wait_val = 43,
    futex_wake = 45,
    idc_read = 23,
    idc_write = 24,
    info_cores = 51,
    info_system = 50,
    map_guest = 29,
    map_mmio = 19,
    map_pf = 18,
    perfmon_info = 13,
    perfmon_read = 15,
    perfmon_start = 14,
    perfmon_stop = 16,
    power_reboot = 53,
    power_screen_off = 55,
    power_set_freq = 56,
    power_set_idle = 57,
    power_shutdown = 52,
    power_sleep = 54,
    priority = 11,
    random = 49,
    recv = 35,
    remap = 21,
    reply = 38,
    reply_transfer = 39,
    restrict = 0,
    revoke = 2,
    self = 8,
    snapshot = 22,
    @"suspend" = 34,
    sync = 3,
    terminate = 9,
    time_getwall = 47,
    time_monotonic = 46,
    time_setwall = 48,
    timer_arm = 40,
    timer_cancel = 42,
    timer_rearm = 41,
    unmap = 20,
    unmap_guest = 30,
    vm_inject_irq = 32,
    vm_set_policy = 31,
    yield = 10,
};

/// Read `args[i]`, returning 0 when the index is past the end. Lets
/// handlers that take fewer args than the max not have to special-case
/// the slice length.
inline fn arg(args: []const u64, i: usize) u64 {
    return if (i < args.len) args[i] else 0;
}

pub fn dispatch(caller: *anyopaque, syscall_word: u64, args: []const u64) i64 {
    // Spec §[syscall]: syscall number lives in bits 0-11 of the syscall
    // word. Anything beyond that range is per-syscall metadata
    // (pair_count, kind, etc.) and is the handler's responsibility.
    const num_raw: u64 = syscall_word & 0xFFF;
    const num = std.meta.intToEnum(SyscallNum, num_raw) catch return errors.E_INVAL;

    return switch (num) {
        .restrict => capability.restrict(caller, arg(args, 0), arg(args, 1)),
        .delete => capability.delete(caller, arg(args, 0)),
        .revoke => capability.revoke(caller, arg(args, 0)),
        .sync => capability.sync(caller, arg(args, 0)),

        .create_capability_domain => capability_domain.createCapabilityDomain(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
            if (args.len > 4) args[4..] else &.{},
        ),
        .acquire_ecs => capability_domain.acquireEcs(caller, arg(args, 0)),
        .acquire_vars => capability_domain.acquireVars(caller, arg(args, 0)),

        .create_execution_context => execution_context.createExecutionContext(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
            arg(args, 4),
            arg(args, 5),
        ),
        .self => execution_context.self(caller),
        .terminate => execution_context.terminate(caller, arg(args, 0)),
        .yield => execution_context.yield(caller, arg(args, 0)),
        .priority => execution_context.priority(caller, arg(args, 0), arg(args, 1)),
        .affinity => execution_context.affinity(caller, arg(args, 0), arg(args, 1)),
        .perfmon_info => execution_context.perfmonInfo(caller),
        .perfmon_start => execution_context.perfmonStart(
            caller,
            arg(args, 0),
            arg(args, 1),
            if (args.len > 2) args[2..] else &.{},
        ),
        .perfmon_read => execution_context.perfmonRead(caller, arg(args, 0)),
        .perfmon_stop => execution_context.perfmonStop(caller, arg(args, 0)),

        .create_var => var_.createVar(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
            arg(args, 4),
        ),
        .map_pf => var_.mapPf(
            caller,
            arg(args, 0),
            if (args.len > 1) args[1..] else &.{},
        ),
        .map_mmio => var_.mapMmio(caller, arg(args, 0), arg(args, 1)),
        .unmap => var_.unmap(
            caller,
            arg(args, 0),
            if (args.len > 1) args[1..] else &.{},
        ),
        .remap => var_.remap(caller, arg(args, 0), arg(args, 1)),
        .snapshot => var_.snapshot(caller, arg(args, 0), arg(args, 1)),
        .idc_read => var_.idcRead(
            caller,
            arg(args, 0),
            arg(args, 1),
            @truncate(arg(args, 2)),
        ),
        .idc_write => var_.idcWrite(
            caller,
            arg(args, 0),
            arg(args, 1),
            if (args.len > 2) args[2..] else &.{},
        ),

        .create_page_frame => page_frame.createPageFrame(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),

        .ack => reply.ack(caller, arg(args, 0)),

        .create_port => port.createPort(caller, arg(args, 0)),
        .@"suspend" => port.@"suspend"(caller, arg(args, 0), arg(args, 1)),
        .recv => port.recv(caller, arg(args, 0)),

        .bind_event_route => event_route.bindEventRoute(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),
        .clear_event_route => event_route.clearEventRoute(caller, arg(args, 0), arg(args, 1)),

        .reply => reply.reply(caller, arg(args, 0)),
        .reply_transfer => reply.replyTransfer(
            caller,
            arg(args, 0),
            if (args.len > 1) args[1..] else &.{},
        ),

        .timer_arm => timer.timerArm(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),
        .timer_rearm => timer.timerRearm(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),
        .timer_cancel => timer.timerCancel(caller, arg(args, 0)),

        .futex_wait_val => futex.futexWaitVal(
            caller,
            arg(args, 0),
            if (args.len > 1) args[1..] else &.{},
        ),
        .futex_wait_change => futex.futexWaitChange(
            caller,
            arg(args, 0),
            if (args.len > 1) args[1..] else &.{},
        ),
        .futex_wake => futex.futexWake(caller, arg(args, 0), arg(args, 1)),

        .create_virtual_machine => virtual_machine.createVirtualMachine(
            caller,
            arg(args, 0),
            arg(args, 1),
        ),
        .create_vcpu => virtual_machine.createVcpu(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
            arg(args, 3),
        ),
        .map_guest => virtual_machine.mapGuest(
            caller,
            arg(args, 0),
            if (args.len > 1) args[1..] else &.{},
        ),
        .unmap_guest => virtual_machine.unmapGuest(
            caller,
            arg(args, 0),
            if (args.len > 1) args[1..] else &.{},
        ),
        .vm_set_policy => virtual_machine.vmSetPolicy(
            caller,
            syscall_word,
            arg(args, 0),
            if (args.len > 1) args[1..] else &.{},
        ),
        .vm_inject_irq => virtual_machine.vmInjectIrq(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),

        .time_monotonic => system.timeMonotonic(caller),
        .time_getwall => system.timeGetwall(caller),
        .time_setwall => system.timeSetwall(caller, arg(args, 0)),
        .random => system.random(caller),
        .info_system => system.infoSystem(caller),
        .info_cores => system.infoCores(caller, arg(args, 0)),
        .power_shutdown => system.powerShutdown(caller),
        .power_reboot => system.powerReboot(caller),
        .power_sleep => system.powerSleep(caller, arg(args, 0)),
        .power_screen_off => system.powerScreenOff(caller),
        .power_set_freq => system.powerSetFreq(caller, arg(args, 0), arg(args, 1)),
        .power_set_idle => system.powerSetIdle(caller, arg(args, 0), arg(args, 1)),
    };
}
