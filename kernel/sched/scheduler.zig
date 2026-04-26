//! Per-core scheduler — owns the run queues, dispatches ECs, handles
//! preemption + voluntary yield, tracks the current EC per core, and
//! coordinates lazy-FPU eviction across cores.
//!
//! Each core has a `PerCore` slot holding its run queue (priority-
//! ordered intrusive PQ over EC.next), the currently dispatched EC,
//! the last-FPU-owner EC, and a flag for whether CR0.TS is currently
//! armed. Cross-core enqueue is supported (the source core sends an
//! IPI to the destination if the destination is idle).
//!
//! STUB.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;

const EcQueue = zag.sched.execution_context.EcQueue;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;

/// Maximum cores the scheduler supports. Matches `affinity` mask width.
pub const MAX_CORES: u8 = 64;

/// Default time slice between preemption ticks. Spec doesn't pin this;
/// 2 ms matches old kernel and is reasonable for a microkernel.
pub const TIMESLICE_NS: u64 = 2_000_000;

/// Per-core scheduler state. One entry per active core in `core_states[]`.
pub const PerCore = struct {
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
pub fn globalInit() !void {}

/// Per-core init — called once per core during SMP bring-up after the
/// core's APIC / GIC is online. Allocates the idle EC for this core.
pub fn perCoreInit() void {}

// ── Dispatch ─────────────────────────────────────────────────────────

/// Pick the next EC to run on the current core: highest-priority
/// non-empty bucket in `run_queue`, FIFO within priority. Falls back
/// to `idle_ec` when the queue is empty.
pub fn dequeue() *ExecutionContext {
    @panic("scheduler.dequeue not implemented");
}

/// Context switch to `ec` on the current core. Saves outgoing EC's
/// state to its `ctx`, swaps address space (if domain changed),
/// updates `current_ec`, applies lazy-FPU policy (arm/clear CR0.TS),
/// loads `ec.ctx` and returns to userspace via iretq/sysretq.
pub fn switchTo(ec: *ExecutionContext) void {
    _ = ec;
}

/// Voluntary yield — current EC drops back into ready, scheduler
/// picks the next. If `target` is non-null and runnable, it runs next.
pub fn yieldTo(target: ?*ExecutionContext) void {
    _ = target;
}

/// Preemption tick — invoked from the per-core timer interrupt when
/// the current EC's quantum expires. Re-enqueues current and dispatches.
pub fn preempt() void {}

// ── Enqueue / current accessors ──────────────────────────────────────

/// Enqueue `ec` on `core`'s run queue. Sends a wake IPI if `core`
/// is currently idle. Used by recv → ready transitions, futex wake,
/// timer fires, etc.
pub fn enqueueOnCore(core: u8, ec: *ExecutionContext) void {
    _ = core;
    _ = ec;
}

/// Enqueue `ec` on the kernel's choice of core, honoring `ec.affinity`.
pub fn enqueue(ec: *ExecutionContext) void {
    _ = ec;
}

/// Remove `ec` from whichever queue it currently occupies. Used by
/// terminate, priority change (reinsert), affinity change (migrate).
pub fn removeFromQueue(ec: *ExecutionContext) void {
    _ = ec;
}

/// Currently dispatched EC on this core (the calling core).
pub fn currentEc() ?*ExecutionContext {
    return core_states[arch.smp.coreID()].current_ec;
}

/// Find which core (if any) is currently running `ec`. Returns null
/// when `ec` is in a queue or blocked.
pub fn coreRunning(ec: *ExecutionContext) ?u8 {
    _ = ec;
    return null;
}

// ── State transitions used by other subsystems ───────────────────────

/// Transition `ec` to ready and enqueue. Used by event delivery
/// resumes (reply, futex wake, timer fire, recv→ready, etc.).
pub fn markReady(ec: *ExecutionContext) void {
    _ = ec;
}

/// Pick the right core for `ec` based on its affinity mask. Honors
/// least-loaded heuristic when affinity allows multiple cores.
fn pickCoreForAffinity(affinity: u64) u8 {
    _ = affinity;
    return 0;
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
