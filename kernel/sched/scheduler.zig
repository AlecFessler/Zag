const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const containers = zag.containers;
const device_registry = zag.devices.registry;
const futex = zag.sched.futex;
const kvm = zag.kvm;
const memory_init = zag.memory.init;
const process_mod = zag.sched.process;
const thread_mod = zag.sched.thread;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const PriorityQueue = containers.priority_queue.PriorityQueue;
const Process = zag.sched.process.Process;
const ProcessAllocator = zag.sched.process.ProcessAllocator;
const SpinLock = zag.sched.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const ThreadAllocator = zag.sched.thread.ThreadAllocator;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const Timer = zag.arch.timer.Timer;
const VCpuAllocator = kvm.vcpu.VCpuAllocator;
const VmAllocator = kvm.vm.VmAllocator;

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
    pq: PriorityQueue = .{},

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
    while (i < count) : (i += 1) {
        if (@atomicLoad(?*Thread, &core_states[i].running_thread, .acquire) == thread) return i;
    }
    return null;
}

/// PMU save/restore hook around `arch.switchTo`. Centralizes the
/// null-guarded calls described in systems.md §6 "PMU Save/Restore Hooks"
/// so every `switchTo` site in this file goes through the same pair.
///
/// The save must fire under the outgoing thread's identity so the final
/// hardware counter values are captured before the context switch, and
/// the restore must fire under the incoming thread's identity so the
/// counters are re-enabled with no mis-accounting window. `arch.switchTo`
/// does not return to this frame — it jumps into the incoming thread's
/// kernel stack. The "return" side of the restore is therefore actually
/// executed the next time the *previously outgoing* thread resumes here.
inline fn switchToWithPmu(outgoing: *Thread, next: *Thread) void {
    if (outgoing.pmu_state) |st| arch.pmuSave(st);
    arch.switchTo(next);
    if (next.pmu_state) |st| arch.pmuRestore(st);
}

/// Remove `thread` from any core's run queue. Used when a remote thread is
/// killed while .ready (so we can deinit it without leaving a dangling pointer).
pub fn removeFromAnyRunQueue(thread: *Thread) void {
    const count = arch.coreCount();
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const state = &core_states[i];
        const irq = state.rq_lock.lockIrqSave();
        const removed = state.rq.remove(thread);
        state.rq_lock.unlockIrqRestore(irq);
        if (removed) return;
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
};

var core_states: [MAX_CORES]PerCoreState align(CACHE_LINE_SIZE) = [_]PerCoreState{.{}} ** MAX_CORES;
var expire_core: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var pinned_cores: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

pub const SchedInterruptContext = struct {
    privilege: zag.perms.privilege.PrivilegePerm,
    thread_ctx: *ArchCpuContext,
};

fn armSchedTimer(state: *PerCoreState, delta_ns: u64) void {
    state.timer.armInterruptTimer(delta_ns);
}

pub fn currentThread() ?*Thread {
    return core_states[arch.coreID()].running_thread;
}

/// Attempt to steal a thread from another core's run queue.
/// Called when the local run queue is empty. Returns the stolen thread or null.
fn tryStealWork(my_core_id: u64) ?*Thread {
    const count = arch.coreCount();
    const pinned = pinned_cores.load(.acquire);

    // Retry loop in case peek succeeds but removal fails (race with another stealer)
    var attempts: u32 = 0;
    while (attempts < 3) : (attempts += 1) {
        var best_thread: ?*Thread = null;
        var best_core: u64 = 0;

        // Peek across all non-pinned cores for the highest priority stealable thread
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            if (i == my_core_id) continue;
            // Skip pinned cores
            if (pinned & (@as(u64, 1) << @intCast(i)) != 0) continue;
            const candidate = core_states[i].rq.pq.peekHighestStealable(@intCast(my_core_id));
            if (candidate) |c| {
                if (best_thread == null) {
                    best_thread = c;
                    best_core = i;
                } else if (@intFromEnum(c.priority) > @intFromEnum(best_thread.?.priority)) {
                    best_thread = c;
                    best_core = i;
                }
            }
        }

        const steal_target = best_thread orelse return null;

        // Lock the candidate's home core and try to remove
        const victim_state = &core_states[best_core];
        const irq = victim_state.rq_lock.lockIrqSave();
        const removed = victim_state.rq.remove(steal_target);
        victim_state.rq_lock.unlockIrqRestore(irq);

        if (removed) return steal_target;
        // Race: thread was scheduled or stolen by someone else, retry
    }
    return null;
}

pub fn schedTimerHandler(ctx: SchedInterruptContext) void {
    const core_id = arch.coreID();
    const state = &core_states[core_id];

    const preempted = state.running_thread.?;

    if (preempted.pinned_exclusive) {
        if (preempted.state == .exited) {
            _ = unpinExclusive(preempted);
        } else {
            const pinned_core = @ctz(preempted.core_affinity orelse 0);
            if (pinned_core == core_id) {
                if (core_id == expire_core.load(.monotonic)) {
                    futex.expireTimedWaiters();
                    expire_core.store((core_id + 1) % arch.coreCount(), .monotonic);
                }
                armSchedTimer(state, SCHED_TIMESLICE_NS);
                return;
            }
            preempted.ctx = ctx.thread_ctx;
            preempted.on_cpu.store(false, .release);
            preempted.state = .ready;
            enqueueOnCore(pinned_core, preempted);
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
            if (core_id == expire_core.load(.monotonic)) {
                futex.expireTimedWaiters();
                expire_core.store((core_id + 1) % arch.coreCount(), .monotonic);
            }
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
            if (core_id == expire_core.load(.monotonic)) {
                futex.expireTimedWaiters();
                expire_core.store((core_id + 1) % arch.coreCount(), .monotonic);
            }
            armSchedTimer(state, SCHED_TIMESLICE_NS);
            if (pinned == preempted) return;
            switchToWithPmu(preempted, pinned);
            return;
        }

        // If current thread IS the pinned thread: never preempt
        if (pinned == preempted) {
            state.rq_lock.unlock();
            if (core_id == expire_core.load(.monotonic)) {
                futex.expireTimedWaiters();
                expire_core.store((core_id + 1) % arch.coreCount(), .monotonic);
            }
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
    if (core_id == expire_core.load(.monotonic)) {
        futex.expireTimedWaiters();
        expire_core.store((core_id + 1) % arch.coreCount(), .monotonic);
    }
    armSchedTimer(state, SCHED_TIMESLICE_NS);
    if (next_thread == preempted) return;
    switchToWithPmu(preempted, next_thread);
}

pub fn yield() void {
    arch.triggerSchedulerInterrupt(arch.coreID());
}

/// Pin the calling thread exclusively to a single core. The thread becomes
/// non-preemptible on that core. Requirements:
/// - Thread must have single-core affinity already set
/// - That core must not already have a pinned thread
/// - At least one core must remain unpinned for preemptive scheduling
/// Returns 0 on success, negative error code on failure.
pub fn pinExclusive(thread: *Thread) i64 {
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
        while (target < count) : (target += 1) {
            if (target == pinned_core) continue;
            const target_bit = @as(u64, 1) << @intCast(target);
            if (pinned_cores.load(.acquire) & target_bit != 0) continue;
            // If thread has affinity, respect it
            if (t.core_affinity) |aff| {
                if (aff & target_bit == 0) continue;
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
    while (target < count) : (target += 1) {
        if (target == exclude_core) continue;
        if (pinned & (@as(u64, 1) << @intCast(target)) != 0) continue;
        if (thread.core_affinity) |aff| {
            if (aff & (@as(u64, 1) << @intCast(target)) == 0) continue;
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
    var target = core_index;

    // If the target core is pinned and this isn't the pinned thread, redirect
    if (!thread.pinned_exclusive) {
        const pinned = pinned_cores.load(.acquire);
        if (pinned & (@as(u64, 1) << @intCast(target)) != 0) {
            // Find an unpinned core
            const count = arch.coreCount();
            var i: u64 = 0;
            while (i < count) : (i += 1) {
                if (pinned & (@as(u64, 1) << @intCast(i)) != 0) continue;
                if (thread.core_affinity) |aff| {
                    if (aff & (@as(u64, 1) << @intCast(i)) == 0) continue;
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
    while (i < count) : (i += 1) {
        const bit = @as(u64, 1) << @intCast(i);
        if (mask & bit != 0 and core_states[i].pinned_thread == null) {
            return i;
        }
    }
    return null;
}

/// Switch to the next ready thread on the current core's run queue.
/// Called from IPC syscalls that block the current thread.
/// The caller must have already set the current thread's state and saved ctx.
/// Does NOT return to the caller — switches stack and jumps to the next thread.
pub fn switchToNextReady() noreturn {
    const core_id = arch.coreID();
    const state = &core_states[core_id];
    // Outgoing is whoever was running on this core before the caller
    // flipped its state to .blocked. We read it *before* overwriting
    // `state.running_thread` so the PMU save fires under the outgoing
    // thread's identity (systems.md §6 "PMU Save/Restore Hooks").
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

pub fn globalInit(root_service_elf: []const u8) !void {
    proc_alloc_instance = try ProcessAllocator.init(memory_init.proc_slab_backing.allocator());
    process_mod.allocator = proc_alloc_instance.allocator();

    thread_alloc_instance = try ThreadAllocator.init(memory_init.thread_slab_backing.allocator());
    thread_mod.allocator = thread_alloc_instance.allocator();

    vm_alloc_instance = try VmAllocator.init(memory_init.kvm_vm_slab_backing.allocator());
    kvm.vm.allocator = vm_alloc_instance.allocator();

    vcpu_alloc_instance = try VCpuAllocator.init(memory_init.kvm_vcpu_slab_backing.allocator());
    kvm.vcpu.allocator = vcpu_alloc_instance.allocator();

    idle_process = try Process.createIdle();

    const root_proc = try Process.create(root_service_elf, .{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .set_affinity = true,
        .restart = true,
        .mem_shm_create = true,
        .device_own = true,
        .fault_handler = true,
    }, null, ThreadHandleRights.full, .pinned);
    device_registry.grantAllToRootService(root_proc);
    core_states[0].rq.enqueue(root_proc.threads[0]);

    initialized = true;
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
    state.idle_thread = idle_thread;
    state.running_thread = idle_thread;

    arch.vmPerCoreInit();
    state.timer = arch.getPreemptionTimer();
    arch.enableInterrupts();
    armSchedTimer(state, SCHED_TIMESLICE_NS);
}
