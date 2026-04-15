const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const futex = zag.proc.futex;
const kprof = zag.kprof.trace_id;
const kprof_dump = zag.kprof.dump;
const kprof_log = zag.kprof.log;
const kprof_mode = zag.kprof.mode;
const kprof_sample = zag.kprof.sample;
const memory_init = zag.memory.init;
const process_mod = zag.proc.process;
const thread_mod = zag.sched.thread;

const ArchCpuContext = arch.ArchCpuContext;
const ThreadPriorityQueue = thread_mod.ThreadPriorityQueue;
const Process = process_mod.Process;
const ProcessAllocator = process_mod.ProcessAllocator;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = thread_mod.Thread;
const ThreadAllocator = thread_mod.ThreadAllocator;
const Timer = zag.arch.timer.Timer;
const VCpuAllocator = arch.VCpuAllocator;
const VmAllocator = arch.VmAllocator;

var proc_alloc_instance: ProcessAllocator = undefined;
var thread_alloc_instance: ThreadAllocator = undefined;
var vm_alloc_instance: VmAllocator = undefined;
var vcpu_alloc_instance: VCpuAllocator = undefined;

pub var idle_process: *Process = undefined;
pub var initialized: bool = false;

const CACHE_LINE_SIZE = 64;
const MAX_CORES = 64;
const SCHED_TIMESLICE_NS = 2_000_000;

const RunQueue = struct {
    pq: ThreadPriorityQueue = .{},

    pub fn enqueue(self: *RunQueue, thread: *Thread) void {
        self.pq.enqueue(thread);
    }

    pub fn dequeue(self: *RunQueue) ?*Thread {
        return self.pq.dequeue();
    }

    pub fn remove(self: *RunQueue, thread: *Thread) bool {
        return self.pq.remove(thread);
    }

    pub fn isEmpty(self: *RunQueue) bool {
        return self.pq.isEmpty();
    }
};

/// Find the core ID currently running `thread`, or null if it's not
/// dispatched anywhere. Used by thread_suspend so the kernel can IPI the
/// right core regardless of whether the thread has explicit affinity.
pub fn coreRunning(thread: *Thread) ?u64 {
    const count = arch.coreCount();
    var i: u64 = 0;
    while (i < count) {
        if (@atomicLoad(?*Thread, &core_states[i].running_thread, .acquire) == thread) return i;
        i += 1;
    }
    return null;
}

/// PMU save/restore hook around `arch.switchTo`. Centralizes the
/// null-guarded calls described in systems.md §run-queue "PMU Save/Restore Hooks"
/// so every `switchTo` site in this file goes through the same pair.
///
/// `arch.switchTo` does not return to this frame — on x64 it mov's RSP to
/// the incoming thread's interrupt frame and jmp's to `interruptStubEpilogue`,
/// which iret's into the incoming thread's userspace. Any code placed after
/// `switchTo` is therefore dead on the incoming side and would only run the
/// next time the *previously outgoing* thread resumes — on its own core, not
/// the incoming thread's core. PMU state is per-core MSR state, so the
/// restore must happen before the switch, while we are still on the core
/// that the incoming thread will run on immediately.
///
/// Ordering: save the outgoing thread's counter values first (this also
/// zeroes `IA32_PERF_GLOBAL_CTRL`, so hardware is quiet), then program the
/// incoming thread's counters via restore, then jump into the incoming
/// thread via `switchTo`. The iret at the end of `switchTo` resumes the
/// incoming thread with its counters already running.
inline fn switchToWithPmu(outgoing: *Thread, next: *Thread) void {
    kprof.enter(.sched_switch_pmu);
    defer kprof.exit(.sched_switch_pmu);
    if (outgoing.pmu_state) |st| arch.pmuSave(st);
    if (next.pmu_state) |st| arch.pmuRestore(st);
    arch.switchTo(next);
}

/// Remove `thread` from any core's run queue. Used when a remote thread is
/// killed while .ready (so we can deinit it without leaving a dangling pointer).
pub fn removeFromAnyRunQueue(thread: *Thread) void {
    kprof.point(.sched_remove_run_queue, 0);
    const count = arch.coreCount();
    var i: u64 = 0;
    while (i < count) {
        const state = &core_states[i];
        const irq = state.rq_lock.lockIrqSave();
        const removed = state.rq.remove(thread);
        state.rq_lock.unlockIrqRestore(irq);
        if (removed) return;
        i += 1;
    }
}

const ExitedThread = struct {
    thread: *Thread,
};

const PerCoreState = struct {
    rq: RunQueue = .{},
    rq_lock: SpinLock = .{},
    running_thread: ?*Thread = null,
    pinned_thread: ?*Thread = null,
    timer: Timer = undefined,
    exited_thread: ?ExitedThread = null,
    idle_thread: ?*Thread = null,
    /// Nanoseconds spent running the idle thread since the last
    /// `sys_info` read-and-reset (§2.15, §6 Idle/Busy Accounting Hook).
    idle_ns: u64 = 0,
    /// Nanoseconds spent running real threads since the last
    /// `sys_info` read-and-reset.
    busy_ns: u64 = 0,
    /// Monotonic-clock timestamp of the previous scheduler tick on this
    /// core. Seeded in `perCoreInit` before the preemption timer is armed;
    /// updated at the top of `schedTimerHandler` when delta is attributed
    /// to `idle_ns` / `busy_ns`.
    last_tick_ns: u64 = 0,
};

var core_states: [MAX_CORES]PerCoreState align(CACHE_LINE_SIZE) = [_]PerCoreState{.{}} ** MAX_CORES;
var expire_core: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var pinned_cores: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

pub const SchedInterruptContext = struct {
    privilege: zag.perms.privilege.PrivilegePerm,
    thread_ctx: *ArchCpuContext,
};

fn armSchedTimer(state: *PerCoreState, delta_ns: u64) void {
    kprof.point(.sched_arm_timer, delta_ns);
    state.timer.armInterruptTimer(delta_ns);
}

/// Per-tick gate for `futex.expireTimedWaiters`. The scan is rotated across
/// cores so a single tick interval only runs it on one core, but the rotation
/// counter advances on every tick regardless of which core matched. That way,
/// if some cores are not currently delivering preemption ticks (e.g. aarch64
/// AP bring-up where secondary cores reach the trampoline but stall before
/// arming their virtual timer), the still-ticking cores eventually cycle
/// through every value of `expire_core` and timed futex waiters are still
/// woken. The previous version stored `(core_id + 1) % cores` only when
/// `cur == core_id`, which deadlocked the rotation on a non-ticking core.
fn maybeExpireTimedWaiters(core_id: u64) void {
    const cores = arch.coreCount();
    while (true) {
        const cur = expire_core.load(.monotonic);
        const next = (cur + 1) % cores;
        if (expire_core.cmpxchgWeak(cur, next, .monotonic, .monotonic)) |_| continue;
        if (cur == core_id) futex.expireTimedWaiters();
        return;
    }
}

pub fn currentThread() ?*Thread {
    return core_states[arch.coreID()].running_thread;
}

pub fn currentProc() *Process {
    return currentThread().?.process;
}

/// Snapshot the idle/busy nanosecond accounting for `core_id`, zeroing
/// both counters atomically as they are read. Used by `sys_info` to
/// deliver per-core utilization data to userspace on every call with a
/// non-null `cores_ptr` (see spec §2.15 and §21).
///
/// Each counter is atomically updated via `@atomicRmw` from the scheduler
/// tick hook in `schedTimerHandler`. The lock is NOT held for those
/// updates; we rely on per-counter atomicity. The pair (idle_ns, busy_ns)
/// is therefore not a transactional snapshot — a reader can see a tick's
/// increment attributed to one side without yet seeing the other. This is
/// acceptable because the drift between sides is bounded by one tick
/// (~2 ms) and far below any reasonable polling cadence.
///
/// `rq_lock.lockIrqSave()` is still acquired here for two purposes, both
/// narrower than a multi-counter transaction:
///
///   * When `core_id` is the caller's own core, IRQ-disable prevents the
///     LOCAL scheduler tick from firing between the `idle_ns` Xchg and
///     the `busy_ns` Xchg and attributing the same tick to both sides.
///     This tightens the per-counter guarantee into a "one tick gap at
///     most" for the local case.
///   * For any `core_id`, the lock serializes concurrent `sys_info`
///     callers sweeping the same core so they don't race each other and
///     lose an accounting window.
///
/// It does NOT stop a REMOTE core's scheduler tick from executing its
/// own `@atomicRmw(.Add, .monotonic)` while the caller's Xchg is in
/// flight — IRQ-disable is scoped to the caller's core only. Cross-core
/// concurrency between this function and `schedTimerHandler` is covered
/// purely by the per-counter atomicity of the RMW pair.
///
/// Returns a pair of (idle_ns, busy_ns) covering the accounting window
/// that ended at this call.
pub fn perCoreReadAndResetAccounting(core_id: u64) struct { idle_ns: u64, busy_ns: u64 } {
    if (core_id >= MAX_CORES) return .{ .idle_ns = 0, .busy_ns = 0 };
    const state = &core_states[core_id];
    const irq = state.rq_lock.lockIrqSave();
    defer state.rq_lock.unlockIrqRestore(irq);
    const idle = @atomicRmw(u64, &state.idle_ns, .Xchg, 0, .monotonic);
    const busy = @atomicRmw(u64, &state.busy_ns, .Xchg, 0, .monotonic);
    return .{ .idle_ns = idle, .busy_ns = busy };
}

fn peekHighestStealable(pq: *const ThreadPriorityQueue, core_id: u6) ?*Thread {
    const core_bit = @as(u64, 1) << core_id;
    var idx: usize = pq.levels.len;
    while (idx > 0) {
        idx -= 1;
        if (idx == @intFromEnum(thread_mod.Priority.pinned)) continue;
        var cur = pq.levels[idx].head;
        while (cur) |c| {
            if (c.core_affinity) |aff| {
                if (aff & core_bit != 0) return c;
            } else {
                return c;
            }
            cur = c.next;
        }
    }
    return null;
}

/// Attempt to steal a thread from another core's run queue.
/// Called when the local run queue is empty. Returns the stolen thread or null.
fn tryStealWork(my_core_id: u64) ?*Thread {
    kprof.enter(.sched_try_steal);
    defer kprof.exit(.sched_try_steal);
    const count = arch.coreCount();
    const pinned = pinned_cores.load(.acquire);

    // Retry loop in case peek succeeds but removal fails (race with another stealer)
    var attempts: u32 = 0;
    while (attempts < 3) {
        var best_thread: ?*Thread = null;
        var best_core: u64 = 0;

        // Peek across all non-pinned cores for the highest priority stealable thread
        var i: u64 = 0;
        while (i < count) {
            if (i == my_core_id) {
                i += 1;
                continue;
            }
            // Skip pinned cores
            if (pinned & (@as(u64, 1) << @intCast(i)) != 0) {
                i += 1;
                continue;
            }
            const candidate = peekHighestStealable(&core_states[i].rq.pq, @intCast(my_core_id));
            if (candidate) |c| {
                if (best_thread == null) {
                    best_thread = c;
                    best_core = i;
                } else if (@intFromEnum(c.priority) > @intFromEnum(best_thread.?.priority)) {
                    best_thread = c;
                    best_core = i;
                }
            }
            i += 1;
        }

        const steal_target = best_thread orelse return null;

        // Lock the candidate's home core and try to remove
        const victim_state = &core_states[best_core];
        const irq = victim_state.rq_lock.lockIrqSave();
        const removed = victim_state.rq.remove(steal_target);
        victim_state.rq_lock.unlockIrqRestore(irq);

        if (removed) return steal_target;
        // Race: thread was scheduled or stolen by someone else, retry
        attempts += 1;
    }
    return null;
}

pub fn schedTimerHandler(ctx: SchedInterruptContext) void {
    kprof.point(.sched_timer_tick, 0);
    if (comptime kprof_mode.any_enabled) {
        if (@atomicLoad(u32, &kprof_log.terminate_requested, .acquire) != 0) {
            kprof_dump.end(.log_full);
        }
    }
    const core_id = arch.coreID();
    const state = &core_states[core_id];

    const preempted = state.running_thread.?;

    // Idle/busy accounting hook (§6, §21). Attribute the elapsed time
    // since the previous tick to either `idle_ns` or `busy_ns` based on
    // whether the thread that just consumed the preceding timeslice was
    // the idle thread. Each counter is updated via a single
    // `@atomicRmw(.Add, .monotonic)`; the lock is NOT held for these
    // updates — we rely on per-counter atomicity. The pair
    // (idle_ns, busy_ns) is therefore not a transactional snapshot for
    // `sys_info` readers: a reader can see a tick's increment attributed
    // to one side without yet seeing the other. This is acceptable
    // because the drift between sides is bounded by one tick (~2 ms),
    // which is far below any reasonable polling cadence. `last_tick_ns`
    // was seeded in `perCoreInit` before the first preemption timer was
    // armed, so the first delta is well-defined.
    const mono = arch.getMonotonicClock();
    const now = mono.now();
    const delta: u64 = now -| state.last_tick_ns;
    const was_idle = (state.idle_thread != null and preempted == state.idle_thread.?);
    if (was_idle) {
        _ = @atomicRmw(u64, &state.idle_ns, .Add, delta, .monotonic);
    } else {
        _ = @atomicRmw(u64, &state.busy_ns, .Add, delta, .monotonic);
    }
    state.last_tick_ns = now;

    // Refresh the per-core hardware-state cache (frequency / temperature /
    // C-state) on this core so that `sys_info` reads from any core see a
    // value at most one tick stale. Must run on the owning core because
    // the underlying `rdmsr` instructions are core-local (§21).
    arch.sampleCoreHwState();

    if (preempted.pinned_exclusive) {
        if (preempted.state == .exited) {
            _ = unpinExclusive(preempted);
        } else {
            const pinned_core = @ctz(preempted.core_affinity orelse 0);
            // §2.2.33: a pinned thread that has blocked (futex/IPC recv) or
            // faulted/suspended temporarily releases its pinned core so other
            // threads can run there. Only the still-runnable (.running /
            // .ready) pinned thread keeps the non-preemption fast path. When
            // the thread later wakes, the wake path re-enqueues it on its
            // pinned core via `enqueueOnCore`, which sends an IPI; the
            // scheduler handler on that core then sees `state.pinned_thread`
            // with state == .ready and preempts back to it (§2.2.34).
            const runnable = preempted.state == .running or preempted.state == .ready;
            if (pinned_core == core_id and runnable) {
                maybeExpireTimedWaiters(core_id);
                armSchedTimer(state, SCHED_TIMESLICE_NS);
                return;
            }
            if (pinned_core == core_id) {
                // Pinned thread non-runnable on its own pinned core —
                // release the core so other threads can run here. Do NOT
                // re-enqueue `preempted`; the wake/unblock path puts it
                // back when its state flips to .ready.
                preempted.ctx = ctx.thread_ctx;
                preempted.on_cpu.store(false, .release);

                state.rq_lock.lock();
                var next = state.rq.dequeue();
                if (next == null) {
                    state.rq_lock.unlock();
                    next = tryStealWork(core_id);
                    state.rq_lock.lock();
                }
                if (next == null) {
                    next = state.idle_thread;
                }
                const next_thread = next.?;
                next_thread.state = .running;
                next_thread.on_cpu.store(true, .release);
                state.running_thread = next_thread;
                state.rq_lock.unlock();
                maybeExpireTimedWaiters(core_id);
                armSchedTimer(state, SCHED_TIMESLICE_NS);
                if (next_thread == preempted) return;
                switchToWithPmu(preempted, next_thread);
                return;
            }
            preempted.ctx = ctx.thread_ctx;
            preempted.on_cpu.store(false, .release);
            if (preempted.state == .running) preempted.state = .ready;
            if (preempted.state == .ready) enqueueOnCore(pinned_core, preempted);
            state.rq_lock.lock();
            var next = state.rq.dequeue();
            if (next == null) {
                state.rq_lock.unlock();
                next = tryStealWork(core_id);
                state.rq_lock.lock();
            }
            if (next == null) {
                next = state.idle_thread;
            }
            const next_thread = next.?;
            next_thread.state = .running;
            next_thread.on_cpu.store(true, .release);
            state.running_thread = next_thread;
            state.rq_lock.unlock();
            maybeExpireTimedWaiters(core_id);
            armSchedTimer(state, SCHED_TIMESLICE_NS);
            if (next_thread == preempted) return;
            switchToWithPmu(preempted, next_thread);
            return;
        }
    }

    preempted.ctx = ctx.thread_ctx;
    preempted.on_cpu.store(false, .release);

    // Clean up the previous-tick exited thread AFTER clearing on_cpu. The exited
    // thread's deinit can cascade through lastThreadExited -> exit -> performRestart ->
    // updateParentView -> futex.wake, which spins on the wake target's on_cpu.
    // If the wake target happens to be the freshly-preempted thread on this
    // very core (e.g., a parent waiting on the dying child's restart futex),
    // and we still had on_cpu set, the wake spin would deadlock against
    // ourselves. Clearing on_cpu first makes the wake's spin a no-op.
    if (state.exited_thread) |exited| {
        exited.thread.deinit();
        state.exited_thread = null;
    }

    state.rq_lock.lock();

    // Check if this core has a pinned_thread that is ready and not currently running
    if (state.pinned_thread) |pinned| {
        if (pinned != preempted and pinned.state == .ready) {
            // Preempt current thread and switch to pinned thread
            if (preempted.state == .running) {
                preempted.state = .ready;
                // Migrate preempted thread to another core
                state.rq_lock.unlock();
                migrateToEligibleCore(preempted, core_id);
                state.rq_lock.lock();
            }
            pinned.state = .running;
            pinned.on_cpu.store(true, .release);
            state.running_thread = pinned;

            if (preempted.state == .exited) {
                state.exited_thread = .{ .thread = preempted };
            }

            state.rq_lock.unlock();
            maybeExpireTimedWaiters(core_id);
            armSchedTimer(state, SCHED_TIMESLICE_NS);
            if (pinned == preempted) return;
            switchToWithPmu(preempted, pinned);
            return;
        }

        // If current thread IS the pinned thread: never preempt
        if (pinned == preempted) {
            state.rq_lock.unlock();
            maybeExpireTimedWaiters(core_id);
            armSchedTimer(state, SCHED_TIMESLICE_NS);
            return;
        }
    }

    // Priority-aware round-robin
    if (preempted.state == .running) {
        preempted.state = .ready;
        // If the thread has affinity that excludes this core, migrate it
        if (preempted.core_affinity) |aff| {
            if (aff & (@as(u64, 1) << @intCast(core_id)) == 0) {
                // Thread shouldn't be on this core — find the right one
                state.rq_lock.unlock();
                enqueueOnCore(@ctz(aff), preempted);
                state.rq_lock.lock();
            } else {
                state.rq.enqueue(preempted);
            }
        } else {
            state.rq.enqueue(preempted);
        }
    }

    var next = state.rq.dequeue();

    // Work stealing: if local queue is empty, try to steal from other cores
    if (next == null) {
        state.rq_lock.unlock();
        next = tryStealWork(core_id);
        state.rq_lock.lock();
    }

    // Fall back to idle thread if nothing else is available
    if (next == null) {
        next = state.idle_thread;
    }

    const next_thread = next.?;
    next_thread.state = .running;
    next_thread.on_cpu.store(true, .release);
    state.running_thread = next_thread;

    if (preempted.state == .exited) {
        state.exited_thread = .{ .thread = preempted };
    }

    state.rq_lock.unlock();
    maybeExpireTimedWaiters(core_id);
    armSchedTimer(state, SCHED_TIMESLICE_NS);
    if (next_thread == preempted) return;
    switchToWithPmu(preempted, next_thread);
}

pub fn yield() void {
    kprof.point(.sched_yield, 0);
    arch.triggerSchedulerInterruptSelf();
}

/// Pin the calling thread exclusively to a single core. The thread becomes
/// non-preemptible on that core. Requirements:
/// - Thread must have single-core affinity already set
/// - That core must not already have a pinned thread
/// - At least one core must remain unpinned for preemptive scheduling
/// Returns 0 on success, negative error code on failure.
pub fn pinExclusive(thread: *Thread) i64 {
    kprof.enter(.sched_pin_exclusive);
    defer kprof.exit(.sched_pin_exclusive);
    const affinity = thread.core_affinity orelse return -1; // E_INVAL: no affinity set
    // Must be exactly one core (power of 2)
    if (affinity == 0 or (affinity & (affinity - 1)) != 0) return -1; // E_INVAL: not single-core

    const core_bit = affinity;

    // Atomically try to claim this core
    while (true) {
        const current = pinned_cores.load(.acquire);
        if (current & core_bit != 0) return -11; // E_BUSY: core already pinned
        const new_pinned = current | core_bit;
        if (pinned_cores.cmpxchgWeak(current, new_pinned, .acq_rel, .acquire)) |_| {
            continue; // CAS failed, retry
        } else {
            break; // CAS succeeded
        }
    }

    thread.pinned_exclusive = true;
    const core_index: u64 = @ctz(core_bit);
    const state = &core_states[core_index];
    state.pinned_thread = thread;

    // Migrate any other threads off this core's run queue
    migrateThreadsOff(state, core_index);

    return @intCast(core_index);
}

/// Move all threads from a pinned core's run queue to other available cores.
fn migrateThreadsOff(state: *PerCoreState, pinned_core: u64) void {
    const count = arch.coreCount();
    const irq = state.rq_lock.lockIrqSave();
    defer state.rq_lock.unlockIrqRestore(irq);

    while (state.rq.dequeue()) |t| {
        // Find an unpinned core to enqueue this thread on
        var target: u64 = 0;
        while (target < count) {
            if (target == pinned_core) {
                target += 1;
                continue;
            }
            const target_bit = @as(u64, 1) << @intCast(target);
            if (pinned_cores.load(.acquire) & target_bit != 0) {
                target += 1;
                continue;
            }
            // If thread has affinity, respect it
            if (t.core_affinity) |aff| {
                if (aff & target_bit == 0) {
                    target += 1;
                    continue;
                }
            }
            break;
        }
        if (target >= count) {
            // No valid target found, put back on core 0 as fallback
            target = 0;
        }
        enqueueOnCore(target, t);
    }
}

/// Migrate a thread to an eligible non-pinned core. Used when a pinned thread
/// preempts the current thread and needs to move it elsewhere.
fn migrateToEligibleCore(thread: *Thread, exclude_core: u64) void {
    const count = arch.coreCount();
    const pinned = pinned_cores.load(.acquire);
    var target: u64 = 0;
    while (target < count) {
        if (target == exclude_core) {
            target += 1;
            continue;
        }
        if (pinned & (@as(u64, 1) << @intCast(target)) != 0) {
            target += 1;
            continue;
        }
        if (thread.core_affinity) |aff| {
            if (aff & (@as(u64, 1) << @intCast(target)) == 0) {
                target += 1;
                continue;
            }
        }
        break;
    }
    if (target >= count) {
        // No eligible core found, enqueue on core 0 as fallback
        target = 0;
    }
    enqueueOnCore(target, thread);
}

/// Unpin a previously pinned thread, restoring preemptive scheduling on its core.
pub fn unpinExclusive(thread: *Thread) i64 {
    kprof.enter(.sched_unpin_exclusive);
    defer kprof.exit(.sched_unpin_exclusive);
    if (!thread.pinned_exclusive) return -1;
    const affinity = thread.core_affinity orelse return -1;
    const core_bit = affinity;

    thread.pinned_exclusive = false;
    const core_index = @ctz(core_bit);
    core_states[core_index].pinned_thread = null;
    _ = pinned_cores.fetchAnd(~core_bit, .release);
    return 0;
}

/// Unpin by core_id — called from revoke_perm on a core_pin handle.
/// Restores the thread's pre-pin priority and affinity.
pub fn unpinByRevoke(core_id: u64) void {
    kprof.enter(.sched_unpin_revoke);
    defer kprof.exit(.sched_unpin_revoke);
    if (core_id >= MAX_CORES) return;
    const state = &core_states[core_id];
    if (state.pinned_thread) |pt| {
        pt.pinned_exclusive = false;
        pt.priority = pt.pre_pin_priority;
        pt.core_affinity = pt.pre_pin_affinity;
        pt.pre_pin_affinity = null;
        state.pinned_thread = null;
        const core_bit = @as(u64, 1) << @intCast(core_id);
        _ = pinned_cores.fetchAnd(~core_bit, .release);
    }
}

pub fn enqueueOnCore(core_index: u64, thread: *Thread) void {
    kprof.point(.sched_enqueue, core_index);
    var target = core_index;

    // If the target core is pinned and this isn't the pinned thread, redirect
    if (!thread.pinned_exclusive) {
        const pinned = pinned_cores.load(.acquire);
        if (pinned & (@as(u64, 1) << @intCast(target)) != 0) {
            // Find an unpinned core
            const count = arch.coreCount();
            var i: u64 = 0;
            while (i < count) {
                if (pinned & (@as(u64, 1) << @intCast(i)) != 0) {
                    i += 1;
                    continue;
                }
                if (thread.core_affinity) |aff| {
                    if (aff & (@as(u64, 1) << @intCast(i)) == 0) {
                        i += 1;
                        continue;
                    }
                }
                target = i;
                break;
            }
        }
    }

    const state = &core_states[target];
    const irq = state.rq_lock.lockIrqSave();
    state.rq.enqueue(thread);
    state.rq_lock.unlockIrqRestore(irq);

    // IPI on thread ready: if the enqueued thread's priority exceeds the
    // currently running thread on this core, send an IPI to preempt immediately.
    const running = @atomicLoad(?*Thread, &state.running_thread, .acquire);
    if (running) |r| {
        if (@intFromEnum(thread.priority) > @intFromEnum(r.priority)) {
            arch.triggerSchedulerInterrupt(target);
        }
    }
}

/// Pick best core for a thread. Prefers current_core if in affinity mask and not pinned.
/// Returns null if all cores in the affinity mask are pinned.
fn pickCoreForThread(thread: *Thread, current_core: u64) ?u64 {
    const mask = thread.core_affinity orelse return current_core;
    const current_bit = @as(u64, 1) << @intCast(current_core);
    if (mask & current_bit != 0 and core_states[current_core].pinned_thread == null) {
        return current_core;
    }
    const count = arch.coreCount();
    var i: u64 = 0;
    while (i < count) {
        const bit = @as(u64, 1) << @intCast(i);
        if (mask & bit != 0 and core_states[i].pinned_thread == null) {
            return i;
        }
        i += 1;
    }
    return null;
}

/// Switch to the next ready thread on the current core's run queue.
/// Called from IPC syscalls that block the current thread.
/// The caller must have already set the current thread's state and saved ctx.
/// Does NOT return to the caller — switches stack and jumps to the next thread.
pub fn switchToNextReady() noreturn {
    kprof.enter(.sched_switch);
    defer kprof.exit(.sched_switch);
    const core_id = arch.coreID();
    const state = &core_states[core_id];
    // Outgoing is whoever was running on this core before the caller
    // flipped its state to .blocked. We read it *before* overwriting
    // `state.running_thread` so the PMU save fires under the outgoing
    // thread's identity (systems.md §run-queue "PMU Save/Restore Hooks").
    const outgoing: ?*Thread = @atomicLoad(?*Thread, &state.running_thread, .acquire);

    state.rq_lock.lock();
    var next = state.rq.dequeue();

    // Work stealing if local queue is empty
    if (next == null) {
        state.rq_lock.unlock();
        next = tryStealWork(core_id);
        state.rq_lock.lock();
    }

    // Fall back to idle thread
    if (next == null) {
        next = state.idle_thread;
    }

    const next_thread = next.?;
    next_thread.state = .running;
    next_thread.on_cpu.store(true, .release);
    state.running_thread = next_thread;
    state.rq_lock.unlock();

    armSchedTimer(state, SCHED_TIMESLICE_NS);
    if (outgoing) |out| {
        switchToWithPmu(out, next_thread);
    } else {
        arch.switchTo(next_thread);
    }
    unreachable;
}

/// Switch directly to a specific target thread. Used by IPC for direct handoff.
/// Saves current thread's context, sets it to blocked/ready, and switches.
/// If enqueue_current is true, the current thread is placed on the run queue
/// after its context is saved (used by reply to keep the server runnable).
/// If the target thread requires a different core (affinity), enqueues it remotely
/// and sends an IPI, then runs next ready thread locally.
/// Returns E_BUSY (-11) if all cores in target's affinity are pinned.
/// Otherwise does NOT return — switches stack.
pub fn switchToThread(current: *Thread, target: *Thread, ctx: *ArchCpuContext, enqueue_current: bool) i64 {
    kprof.enter(.sched_switch_direct);
    defer kprof.exit(.sched_switch_direct);
    current.ctx = ctx;
    current.on_cpu.store(false, .release);

    const current_core = arch.coreID();
    const target_core = pickCoreForThread(target, current_core) orelse {
        // Undo — caller must handle this error
        current.on_cpu.store(true, .release);
        return -11; // E_BUSY
    };

    // Enqueue current thread after ctx is saved but before switching
    if (enqueue_current) {
        enqueueOnCore(current_core, current);
    }

    const state = &core_states[current_core];

    if (target_core == current_core) {
        target.state = .running;
        target.on_cpu.store(true, .release);
        state.running_thread = target;
        armSchedTimer(state, SCHED_TIMESLICE_NS);
        switchToWithPmu(current, target);
    } else {
        target.state = .ready;
        enqueueOnCore(target_core, target);
        arch.triggerSchedulerInterrupt(target_core);
        // Run next ready thread locally
        state.rq_lock.lock();
        var next = state.rq.dequeue();

        // Work stealing if local queue is empty
        if (next == null) {
            state.rq_lock.unlock();
            next = tryStealWork(current_core);
            state.rq_lock.lock();
        }

        // Fall back to idle thread
        if (next == null) {
            next = state.idle_thread;
        }

        const next_thread = next.?;
        next_thread.state = .running;
        next_thread.on_cpu.store(true, .release);
        state.running_thread = next_thread;
        state.rq_lock.unlock();
        armSchedTimer(state, SCHED_TIMESLICE_NS);
        switchToWithPmu(current, next_thread);
    }
    unreachable;
}

pub fn globalInit() !void {
    proc_alloc_instance = try ProcessAllocator.init(memory_init.proc_slab_backing.allocator());
    process_mod.allocator = proc_alloc_instance.allocator();

    thread_alloc_instance = try ThreadAllocator.init(memory_init.thread_slab_backing.allocator());
    thread_mod.allocator = thread_alloc_instance.allocator();

    vm_alloc_instance = try VmAllocator.init(memory_init.kvm_vm_slab_backing.allocator());
    arch.kvmSetVmAllocator(vm_alloc_instance.allocator());

    vcpu_alloc_instance = try VCpuAllocator.init(memory_init.kvm_vcpu_slab_backing.allocator());
    arch.kvmSetVcpuAllocator(vcpu_alloc_instance.allocator());

    idle_process = try Process.createIdle();

    initialized = true;
}

/// Idle loop entry for per-core idle threads. Runs at kernel privilege and
/// blocks on `halt` until the next interrupt (timer/IPI). aarch64 needs a
/// real entry and kernel stack because its `switchTo` path uses
/// `thread.kernel_stack` to seed SP_EL1 and `thread.ctx` to ERET into the
/// idle body. On x86_64 the existing path never ERETs into the idle thread
/// (IRQs run on top of whatever context was already executing and TSS.rsp0
/// is reprogrammed only on EL0→EL1 transitions), so leaving the idle fields
/// undefined there remains a no-op.
fn idleLoop() void {
    while (true) arch.halt();
}

pub fn perCoreInit() void {
    const core_id = arch.coreID();
    const state = &core_states[core_id];

    // Create a real idle thread for this core
    const idle_thread = thread_mod.allocator.create(Thread) catch @panic("failed to allocate idle thread");
    idle_thread.* = .{
        .tid = std.math.maxInt(u64) - core_id,
        .ctx = undefined,
        .kernel_stack = undefined,
        .user_stack = null,
        .process = idle_process,
        .state = .running,
        .on_cpu = std.atomic.Value(bool).init(true),
        .priority = .idle,
    };
    if (@import("builtin").cpu.arch == .aarch64) {
        // aarch64 requires a concrete kernel stack and entry context for
        // the idle thread because every thread switch reseats SP_EL1 from
        // `thread.kernel_stack.top` and ERETs into `thread.ctx`.
        idle_thread.kernel_stack = thread_mod.createKernelStack() catch @panic("failed to allocate idle kernel stack");
        const idle_kstack_top = address.alignStack(idle_thread.kernel_stack.top);
        idle_thread.ctx = arch.prepareThreadContext(idle_kstack_top, null, &idleLoop, 0);
    }
    state.idle_thread = idle_thread;
    state.running_thread = idle_thread;

    arch.vmPerCoreInit();
    arch.pmuPerCoreInit();
    kprof_sample.perCoreInit();
    kprof.perCoreInit();
    arch.sysInfoPerCoreInit();
    state.timer = arch.getPreemptionTimer();

    // Seed `last_tick_ns` from the monotonic clock before the preemption
    // timer is armed (§6 Idle/Busy Accounting Hook). Until this point
    // `idle_ns` and `busy_ns` are zero; the first tick's delta lands
    // cleanly on a well-defined prior timestamp.
    state.last_tick_ns = arch.getMonotonicClock().now();

    arch.enableInterrupts();
    armSchedTimer(state, SCHED_TIMESLICE_NS);
}
