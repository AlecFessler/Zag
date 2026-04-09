const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const device_registry = zag.devices.registry;
const futex = zag.sched.futex;
const memory_init = zag.memory.init;
const process_mod = zag.sched.process;
const thread_mod = zag.sched.thread;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const Process = zag.sched.process.Process;
const ProcessAllocator = zag.sched.process.ProcessAllocator;
const SpinLock = zag.sched.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const ThreadAllocator = zag.sched.thread.ThreadAllocator;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const Timer = zag.arch.timer.Timer;

var proc_alloc_instance: ProcessAllocator = undefined;
var thread_alloc_instance: ThreadAllocator = undefined;

pub var idle_process: *Process = undefined;
pub var initialized: bool = false;

const CACHE_LINE_SIZE = 64;
const MAX_CORES = 64;
const SCHED_TIMESLICE_NS = 2_000_000;

const RunQueue = struct {
    sentinel: Thread,
    head: *Thread,
    tail: *Thread,

    pub fn init(self: *RunQueue) void {
        self.sentinel = .{
            .tid = std.math.maxInt(u64),
            .ctx = undefined,
            .kernel_stack = undefined,
            .user_stack = null,
            .process = idle_process,
            .next = null,
            .core_affinity = null,
            .state = .running,
            .on_cpu = std.atomic.Value(bool).init(false),
        };
        self.head = &self.sentinel;
        self.tail = &self.sentinel;
    }

    pub fn enqueue(self: *RunQueue, thread: *Thread) void {
        thread.next = null;
        self.tail.next = thread;
        self.tail = thread;
    }

    pub fn dequeue(self: *RunQueue) ?*Thread {
        // Skip non-runnable threads (suspended, faulted).
        // .exited is NOT skipped here — those threads continue running until
        // they hit the scheduler-zombie path on the next preemption.
        while (true) {
            const first = self.head.next orelse return null;
            if (self.tail == first) {
                self.tail = self.head;
            }
            self.head.next = first.next;
            first.next = null;
            if (first.state == .suspended or first.state == .faulted) {
                continue;
            }
            return first;
        }
    }

    /// Remove `thread` from this queue if present. Returns true if removed.
    pub fn remove(self: *RunQueue, thread: *Thread) bool {
        var prev: *Thread = self.head;
        while (prev.next) |cur| {
            if (cur == thread) {
                prev.next = cur.next;
                if (self.tail == cur) self.tail = prev;
                cur.next = null;
                return true;
            }
            prev = cur;
        }
        return false;
    }
};

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

const Zombie = struct {
    thread: *Thread,
};

const PerCoreState = struct {
    rq: RunQueue = undefined,
    rq_lock: SpinLock = .{},
    running_thread: ?*Thread = null,
    timer: Timer = undefined,
    zombie: ?Zombie = null,
    pinned_thread: ?*Thread = null,
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

pub fn schedTimerHandler(ctx: SchedInterruptContext) void {
    const core_id = arch.coreID();
    const state = &core_states[core_id];

    const preempted = state.running_thread.?;

    // Non-preemptible pinned threads: normally skip the context switch.
    // But if the thread has been killed (.exited), unpin it and fall through
    // to normal scheduling so it can be cleaned up as a zombie.
    if (preempted.pinned_exclusive) {
        if (preempted.state == .exited) {
            _ = unpinExclusive(preempted);
        } else {
            if (core_id == expire_core.load(.monotonic)) {
                futex.expireTimedWaiters();
                expire_core.store((core_id + 1) % arch.coreCount(), .monotonic);
            }
            armSchedTimer(state, SCHED_TIMESLICE_NS);
            return;
        }
    }

    preempted.ctx = ctx.thread_ctx;
    preempted.on_cpu.store(false, .release);

    // Clean up the previous-tick zombie AFTER clearing on_cpu. The zombie's
    // deinit can cascade through lastThreadExited → exit → performRestart →
    // updateParentView → futex.wake, which spins on the wake target's on_cpu.
    // If the wake target happens to be the freshly-preempted thread on this
    // very core (e.g., a parent waiting on the dying child's restart futex),
    // and we still had on_cpu set, the wake spin would deadlock against
    // ourselves. Clearing on_cpu first makes the wake's spin a no-op.
    if (state.zombie) |zombie| {
        zombie.thread.deinit();
        state.zombie = null;
    }

    state.rq_lock.lock();

    if (preempted != &state.rq.sentinel and preempted.state == .running) {
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

    const next = state.rq.dequeue() orelse &state.rq.sentinel;
    if (next != &state.rq.sentinel) {
        next.state = .running;
        next.on_cpu.store(true, .release);
    }
    state.running_thread = next;

    if (preempted != &state.rq.sentinel and preempted.state == .exited) {
        state.zombie = .{ .thread = preempted };
    }

    state.rq_lock.unlock();
    if (core_id == expire_core.load(.monotonic)) {
        futex.expireTimedWaiters();
        expire_core.store((core_id + 1) % arch.coreCount(), .monotonic);
    }
    armSchedTimer(state, SCHED_TIMESLICE_NS);
    if (next == preempted) return;
    arch.switchTo(next);
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
    const count = arch.coreCount();
    const all_cores: u64 = if (count >= 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(count)) - 1;

    // Atomically try to claim this core
    while (true) {
        const current = pinned_cores.load(.acquire);
        if (current & core_bit != 0) return -11; // E_BUSY: core already pinned
        // At least one core must remain unpinned
        const new_pinned = current | core_bit;
        if (new_pinned == all_cores) return -1; // E_INVAL: would pin all cores
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

/// Unpin by core_id and thread_tid — called from revoke_perm on a core_pin handle.
pub fn unpinByRevoke(core_id: u64, thread_tid: u64) void {
    if (core_id >= MAX_CORES) return;
    const state = &core_states[core_id];
    if (state.pinned_thread) |pt| {
        if (pt.tid == thread_tid) {
            pt.pinned_exclusive = false;
            state.pinned_thread = null;
            const core_bit = @as(u64, 1) << @intCast(core_id);
            _ = pinned_cores.fetchAnd(~core_bit, .release);
        }
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

    state.rq_lock.lock();
    const next = state.rq.dequeue() orelse &state.rq.sentinel;
    if (next != &state.rq.sentinel) {
        next.state = .running;
        next.on_cpu.store(true, .release);
    }
    state.running_thread = next;
    state.rq_lock.unlock();

    armSchedTimer(state, SCHED_TIMESLICE_NS);
    arch.switchTo(next);
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
        arch.switchTo(target);
    } else {
        target.state = .ready;
        enqueueOnCore(target_core, target);
        arch.triggerSchedulerInterrupt(target_core);
        // Run next ready thread locally
        state.rq_lock.lock();
        const next = state.rq.dequeue() orelse &state.rq.sentinel;
        if (next != &state.rq.sentinel) {
            next.state = .running;
            next.on_cpu.store(true, .release);
        }
        state.running_thread = next;
        state.rq_lock.unlock();
        armSchedTimer(state, SCHED_TIMESLICE_NS);
        arch.switchTo(next);
    }
    unreachable;
}

pub fn globalInit(root_service_elf: []const u8) !void {
    proc_alloc_instance = try ProcessAllocator.init(memory_init.proc_slab_backing.allocator());
    process_mod.allocator = proc_alloc_instance.allocator();

    thread_alloc_instance = try ThreadAllocator.init(memory_init.thread_slab_backing.allocator());
    thread_mod.allocator = thread_alloc_instance.allocator();

    idle_process = try Process.createIdle();

    for (&core_states) |*state| {
        state.rq.init();
    }

    const root_proc = try Process.create(root_service_elf, .{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .set_affinity = true,
        .restart = true,
        .shm_create = true,
        .device_own = true,
        .pin_exclusive = true,
        .fault_handler = true,
    }, null, ThreadHandleRights.full);
    device_registry.grantAllToRootService(root_proc);
    core_states[0].rq.enqueue(root_proc.threads[0]);

    initialized = true;
}

pub fn perCoreInit() void {
    const state = &core_states[arch.coreID()];
    state.running_thread = &state.rq.sentinel;
    state.timer = arch.getPreemptionTimer();
    arch.enableInterrupts();
    armSchedTimer(state, SCHED_TIMESLICE_NS);
}
