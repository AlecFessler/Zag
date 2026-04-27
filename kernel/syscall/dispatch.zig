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
            arg(args, 4),
            if (args.len > 5) args[5..] else &.{},
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
        .map_pf => blk: {
            // Spec §[var].map_pf: syscall word bits 12-19 carry N, the
            // number of (offset, page_frame) pairs. The pairs occupy
            // vregs 2..2+2N-1 — args[1..1+2N]. Without this slice the
            // handler sees uninitialized vregs as junk pairs.
            const n: u64 = (syscall_word >> 12) & 0xFF;
            const pair_words: usize = @intCast(n * 2);
            const end_idx: usize = @min(1 + pair_words, args.len);
            break :blk var_.mapPf(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .map_mmio => var_.mapMmio(caller, arg(args, 0), arg(args, 1)),
        .unmap => blk: {
            // Spec §[var].unmap: syscall word bits 12-19 carry N, the
            // number of selectors (0 = unmap everything). The selectors
            // occupy vregs 2..1+N — args[1..1+N]. Without this slice the
            // handler sees uninitialized vregs above the user's payload
            // as junk selectors (e.g. a `&.{}` call would gate into the
            // map=1/3 selector arms and trip E_BADCAP / E_INVAL on
            // garbage values, breaking the N=0 "unmap everything" path).
            const n: u64 = (syscall_word >> 12) & 0xFF;
            const end_idx: usize = @min(1 + @as(usize, @intCast(n)), args.len);
            break :blk var_.unmap(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .remap => var_.remap(caller, arg(args, 0), arg(args, 1)),
        .snapshot => var_.snapshot(caller, arg(args, 0), arg(args, 1)),
        .idc_read => blk: {
            // Spec §[var].idc_read: syscall word bits 12-19 carry count
            // (number of qwords, max 125). Args carry only [1] var and
            // [2] offset — vreg 3 onwards holds the *return* qwords, so
            // sourcing count from `arg(args, 2)` would read whatever the
            // caller left in rdx (typically 0) and trip the count-zero
            // guard before the BADCAP / alignment / size checks ever
            // run, breaking [test 01] / [test 02] / [test 07] / [test 08].
            const n: u8 = @truncate((syscall_word >> 12) & 0xFF);
            break :blk var_.idcRead(
                caller,
                arg(args, 0),
                arg(args, 1),
                n,
            );
        },
        .idc_write => blk: {
            // Spec §[var].idc_write: syscall word bits 12-19 carry count
            // (number of qwords, max 125). Qwords occupy vregs 3..2+count
            // — args[2..2+count]. The handler needs the *raw* count
            // (before slice truncation) so it can return E_INVAL for
            // count > 125 even though the args slice tops out at 13
            // entries (test 04 boundary).
            const n: u8 = @truncate((syscall_word >> 12) & 0xFF);
            const end_idx: usize = @min(2 + @as(usize, n), args.len);
            break :blk var_.idcWrite(
                caller,
                arg(args, 0),
                arg(args, 1),
                n,
                if (end_idx > 2) args[2..end_idx] else &.{},
            );
        },

        .create_page_frame => page_frame.createPageFrame(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),

        .ack => reply.ack(caller, arg(args, 0)),

        .create_port => port.createPort(caller, arg(args, 0)),
        .@"suspend" => blk: {
            // Spec §[handle_attachments]: syscall word bits 12-19 carry
            // `pair_count` `N`. When N > 0 the [2] port handle must
            // carry the `xfer` cap (test 01), entries must be valid,
            // etc. The handler needs the count to gate that check.
            const pair_count: u8 = @truncate((syscall_word >> 12) & 0xFF);
            break :blk port.@"suspend"(caller, arg(args, 0), arg(args, 1), pair_count);
        },
        .recv => port.recv(caller, arg(args, 0), arg(args, 1)),

        .bind_event_route => event_route.bindEventRoute(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),
        .clear_event_route => event_route.clearEventRoute(caller, arg(args, 0), arg(args, 1)),

        .reply => reply.reply(caller, arg(args, 0)),
        .reply_transfer => blk: {
            // Spec §[reply].reply_transfer: syscall word bits 12-19 carry
            // `pair_count` `N`. Spec §[handle_attachments] places the N
            // pair entries at vregs [128-N..127], but the v0 runner only
            // sources register vregs (1..13); for the register-only path
            // we map the entries into args[1..1+N]. Without this slice
            // the handler sees uninitialized vregs above the user's
            // payload as junk pair entries and trips the
            // pair-entry-reserved-bits gate (test 04) before the
            // handle-resolve gate (test 01) can fire.
            const n: u64 = (syscall_word >> 12) & 0xFF;
            const end_idx: usize = @min(1 + @as(usize, @intCast(n)), args.len);
            break :blk reply.replyTransfer(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },

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

        .futex_wait_val => blk: {
            // Spec §[futex_wait_val]: syscall word bits 12-19 carry N
            // (number of (addr, expected) pairs, 1..63). The pairs
            // occupy vregs 2..1+2N — args[1..1+2N]. Without this slice
            // the handler sees uninitialized vregs as junk pairs.
            //
            // [test 02] N = 0 or N > 63 must surface E_INVAL. We
            // validate the raw N here BEFORE slicing — otherwise an
            // out-of-range N could silently truncate to a smaller
            // valid count once clamped against args.len, masking the
            // bounds violation.
            const n: u64 = (syscall_word >> 12) & 0xFF;
            if (n == 0 or n > 63) break :blk errors.E_INVAL;
            const pair_words: usize = @intCast(n * 2);
            const end_idx: usize = @min(1 + pair_words, args.len);
            break :blk futex.futexWaitVal(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .futex_wait_change => blk: {
            // Spec §[futex_wait_change]: identical N-bounds rule as
            // futex_wait_val — see comment above.
            const n: u64 = (syscall_word >> 12) & 0xFF;
            if (n == 0 or n > 63) break :blk errors.E_INVAL;
            const pair_words: usize = @intCast(n * 2);
            const end_idx: usize = @min(1 + pair_words, args.len);
            break :blk futex.futexWaitChange(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
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
        .map_guest => blk: {
            // Spec §[virtual_machine].map_guest: syscall word bits 12-19
            // carry N, the number of (guest_addr, page_frame) pairs. The
            // pairs occupy vregs 2..2+2N-1 — args[1..1+2N]. Without this
            // slice the handler sees uninitialized vregs above the user's
            // payload as junk pairs (pairs.len ends up odd or carries
            // garbage handles, tripping E_INVAL/E_BADCAP before the
            // user's actual error path can fire).
            const n: u64 = (syscall_word >> 12) & 0xFF;
            const pair_words: usize = @intCast(n * 2);
            const end_idx: usize = @min(1 + pair_words, args.len);
            break :blk virtual_machine.mapGuest(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .unmap_guest => blk: {
            // Spec §[virtual_machine].unmap_guest: syscall word bits 12-19
            // carry N, the number of page_frames to unmap. The handles
            // occupy vregs 2..1+N — args[1..1+N]. Without this slice the
            // handler sees uninitialized vregs above the user's payload
            // as junk handles, tripping E_BADCAP before the user's
            // intended error path runs.
            const n: u64 = (syscall_word >> 12) & 0xFF;
            const end_idx: usize = @min(1 + @as(usize, @intCast(n)), args.len);
            break :blk virtual_machine.unmapGuest(
                caller,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .vm_set_policy => blk: {
            // Spec §[virtual_machine].vm_set_policy: syscall word bit 12
            // = kind, bits 13-20 = count. Each entry occupies a per-arch,
            // per-kind number of vregs (3 on x86-64 for kind 0/1; 2 or 3
            // on aarch64 per §[vm_set_policy]). The handler resolves the
            // exact vreg count against count + the (kind, arch) layout;
            // dispatch hands it the full vreg space above [1] so the
            // handler can validate `entries.len == count * vregs/entry`
            // and reject malformed wires.
            const end_idx: usize = args.len;
            break :blk virtual_machine.vmSetPolicy(
                caller,
                syscall_word,
                arg(args, 0),
                if (end_idx > 1) args[1..end_idx] else &.{},
            );
        },
        .vm_inject_irq => virtual_machine.vmInjectIrq(
            caller,
            arg(args, 0),
            arg(args, 1),
            arg(args, 2),
        ),

        .time_monotonic => system.timeMonotonic(caller),
        .time_getwall => system.timeGetwall(caller),
        .time_setwall => system.timeSetwall(caller, arg(args, 0)),
        .random => blk: {
            // Spec §[rng] random: count packed in syscall word bits 12-19.
            const count: u8 = @truncate((syscall_word >> 12) & 0xFF);
            break :blk system.random(caller, count);
        },
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
