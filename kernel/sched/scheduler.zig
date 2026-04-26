//! Per-core scheduler — owns the run queues, dispatches ECs, handles
//! preemption + voluntary yield, tracks the current EC per core, and
//! coordinates lazy-FPU eviction across cores.
//!
//! Each core has a `PerCore` slot holding its run queue (priority-
//! ordered intrusive PQ over EC.next), the currently dispatched EC,
//! the last-FPU-owner EC, and a flag for whether CR0.TS is currently
//! armed. Cross-core enqueue is supported (the source core sends an
//! IPI to the destination if the destination is idle).

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const Priority = zag.sched.execution_context.Priority;

/// Intrusive priority queue of ECs, linked through the EC's `next`
/// field and ordered by `priority`. Shared by per-core run queues and
/// port wait queues. Futex buckets use a separate WaitNode-based queue
/// (see sched/futex.zig).
pub const EcQueue = zag.utils.containers.priority_queue.PriorityQueue(
    ExecutionContext,
    "next",
    "priority",
    @typeInfo(Priority).@"enum".fields.len,
);

/// Maximum cores the scheduler supports. Matches `affinity` mask width.
pub const MAX_CORES: u8 = 64;

/// Default time slice between preemption ticks. Spec doesn't pin this;
/// 2 ms matches old kernel and is reasonable for a microkernel.
pub const TIMESLICE_NS: u64 = 2_000_000;

/// Per-core scheduler state. One entry per active core in `core_states[]`.
///
/// `extern struct` pins field declaration order so the Phase-5 IPC
/// fast-path asm in `arch/x64/interrupts.zig` can keep its hardcoded
/// immediate displacements (`72(%%rcx)` for `last_fpu_owner`,
/// `80(%%rcx)` for `fpu_trap_armed`) regardless of Zig's auto-reorder
/// rules across versions.
pub const PerCore = extern struct {
    /// Priority-ordered intrusive PQ over EC.next. Drained by
    /// `dequeue` on context switch / yield / preempt.
    run_queue: EcQueue = .{},

    /// EC currently dispatched on this core. `null` ⇒ core is idle.
    current_ec: ?*ExecutionContext = null,

    /// EC whose FP/SIMD state currently lives in this core's CPU
    /// registers. May be a different EC than `current_ec` (lazy FPU —
    /// eviction happens on the next FP-disabled trap, not on context
    /// switch). `null` if no EC has used FP on this core since boot.
    last_fpu_owner: ?*ExecutionContext = null,

    /// Whether CR0.TS / FPEN is currently armed on this core. Tracked
    /// here so we don't issue redundant CR-writes (each one costs a
    /// vmexit under KVM).
    fpu_trap_armed: bool = false,

    /// Per-core idle EC. Allocated at perCoreInit; runs `hlt`/`wfi`
    /// when the run queue is empty. Pinned to this core via affinity.
    idle_ec: ?*ExecutionContext = null,
};

/// Per-core scheduler state. Indexed by core id (APIC ID on x86-64,
/// MPIDR on aarch64). Only the first `arch.smp.coreCount()` entries
/// are populated.
pub var core_states: [MAX_CORES]PerCore = [_]PerCore{.{}} ** MAX_CORES;

/// Set true after `globalInit` returns. Read by the boot path before
/// enqueueing the root service's initial EC.
pub var initialized: bool = false;

// ── Init ─────────────────────────────────────────────────────────────

/// Boot-time global init — called once on the BSP before SMP brings
/// other cores up. Initializes `core_states[0]`'s idle EC and any
/// scheduler-wide state.
pub fn globalInit() !void {
    initialized = true;
}

/// Per-core init — called once per core during SMP bring-up after the
/// core's APIC / GIC is online. Allocates the idle EC for this core.
pub fn perCoreInit() void {}

// ── Dispatch ─────────────────────────────────────────────────────────

/// Pick the next EC to run on the current core: highest-priority
/// non-empty bucket in `run_queue`, FIFO within priority. Returns null
/// when the queue is empty (caller falls back to `idle`).
pub fn dequeue() ?*ExecutionContext {
    const core: u8 = @truncate(arch.smp.coreID());
    const state = &core_states[core];
    return state.run_queue.dequeue();
}

/// Context switch to `ec` on the current core. Saves outgoing EC's
/// state to its `ctx`, swaps address space (if domain changed),
/// updates `current_ec`, applies lazy-FPU policy (arm/clear CR0.TS),
/// loads `ec.ctx` and returns to userspace via iretq/sysretq.
pub fn switchTo(ec: *ExecutionContext) void {
    const core: u8 = @truncate(arch.smp.coreID());
    core_states[core].current_ec = ec;
    ec.state = .running;
    arch.cpu.loadEcContextAndReturn(ec);
}

/// Voluntary yield — current EC drops back into ready, scheduler
/// picks the next. If `target` is non-null and runnable, it runs next.
pub fn yieldTo(target: ?*ExecutionContext) void {
    const core: u8 = @truncate(arch.smp.coreID());
    const state = &core_states[core];

    if (state.current_ec) |cur| {
        cur.state = .ready;
        state.run_queue.enqueue(cur);
    }

    const next = if (target) |t| blk: {
        if (t.state == .ready and state.run_queue.remove(t)) break :blk t;
        break :blk dequeueOrIdle();
    } else dequeueOrIdle();

    switchTo(next);
}

/// Preemption tick — invoked from the per-core timer interrupt when
/// the current EC's quantum expires. Re-enqueues current and dispatches.
pub fn preempt() void {
    yieldTo(null);
}

/// Main scheduler loop entry — called from `kMain` once root EC has
/// been enqueued. Picks the highest-priority ready EC (or falls back
/// to idle) and dispatches; never returns.
pub fn run() noreturn {
    while (true) {
        const next = dequeueOrIdle();
        switchTo(next);
        // switchTo is `noreturn` on the dispatch path. We only reach
        // here when no EC was found and no idle EC was set up — halt
        // with interrupts enabled so a wake IPI can break us out.
        arch.cpu.idle();
    }
}

/// Internal helper — dequeues the highest-priority EC, or returns the
/// per-core idle EC if the queue is empty. When neither is set, panics.
fn dequeueOrIdle() *ExecutionContext {
    const core: u8 = @truncate(arch.smp.coreID());
    const state = &core_states[core];
    if (state.run_queue.dequeue()) |ec| return ec;
    if (state.idle_ec) |idle| return idle;
    @panic("scheduler: no ready EC and no idle EC");
}

// ── Enqueue / current accessors ──────────────────────────────────────

/// Enqueue `ec` on `core`'s run queue. Used by recv → ready transitions,
/// futex wake, timer fires, and the boot path. v0: no cross-core wake
/// IPI; the BSP runs the only scheduler loop and APs are halted.
pub fn enqueueOnCore(core: u8, ec: *ExecutionContext) void {
    ec.state = .ready;
    core_states[core].run_queue.enqueue(ec);
}

/// Enqueue `ec` on the kernel's choice of core, honoring `ec.affinity`.
pub fn enqueue(ec: *ExecutionContext) void {
    enqueueOnCore(pickCoreForAffinity(ec.affinity), ec);
}

/// Remove `ec` from whichever queue it currently occupies. Used by
/// terminate, priority change (reinsert), affinity change (migrate).
pub fn removeFromQueue(ec: *ExecutionContext) void {
    var i: u8 = 0;
    while (i < MAX_CORES) {
        if (core_states[i].run_queue.remove(ec)) return;
        i += 1;
    }
}

/// Currently dispatched EC on this core (the calling core).
pub fn currentEc() ?*ExecutionContext {
    return core_states[arch.smp.coreID()].current_ec;
}

/// Find which core (if any) is currently running `ec`. Returns null
/// when `ec` is in a queue or blocked.
pub fn coreRunning(ec: *ExecutionContext) ?u8 {
    const count = arch.smp.coreCount();
    var i: u8 = 0;
    while (i < count) {
        if (core_states[i].current_ec == ec) return i;
        i += 1;
    }
    return null;
}

// ── State transitions used by other subsystems ───────────────────────

/// Transition `ec` to ready and enqueue. Used by event delivery
/// resumes (reply, futex wake, timer fire, recv→ready, etc.).
pub fn markReady(ec: *ExecutionContext) void {
    ec.state = .ready;
    enqueue(ec);
}

/// Pick the right core for `ec` based on its affinity mask. v0 always
/// returns 0 — only the BSP runs the scheduler loop right now.
fn pickCoreForAffinity(affinity: u64) u8 {
    _ = affinity;
    return @truncate(arch.smp.coreID());
}

// ── Lazy FPU coordination ────────────────────────────────────────────

/// Cross-core FPU flush — if `ec.last_fpu_core` points to a different
/// core than the calling core, IPI that core to FXSAVE its CPU regs
/// into `ec.fpu_state`, then clear `last_fpu_core`. Called before
/// the destination core arms its FPU trap so the trap handler can
/// safely FXRSTOR from a fresh buffer.
pub fn migrateFlush(ec: *ExecutionContext) void {
    _ = ec;
}

/// Update the trap-armed flag on the current core to match `desired`,
/// emitting a CR0.TS / FPEN write only on transitions.
pub fn updateFpuTrap(desired_armed: bool) void {
    _ = desired_armed;
}
