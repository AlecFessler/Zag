//! Port — rendezvous point between a calling EC and a receiving EC,
//! used for IDC, capability transfer, and EC event delivery.
//! See docs/kernel/specv3.md §[port].
//!
//! Lifecycle invariant: a port is alive iff
//!     send_refcount + recv_refcount + event_route_count > 0.
//! No separate lifecycle refcount is tracked. A handle that carries
//! only `copy`/`move`/`restart_policy` (no `bind`, `xfer`, or `recv`)
//! authorizes nothing operational on the port and so does not keep it
//! alive — once every holder is in that useless state the port is
//! cleaned up. The decrementer that drives the last of the three
//! counters to 0 owns teardown, performed under `_gen_lock`.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const capability = zag.caps.capability;
const capability_domain = zag.capdom.capability_domain;
const errors = zag.syscall.errors;
const execution_context = zag.sched.execution_context;
const scheduler = zag.sched.scheduler;

const CapabilityDomain = capability_domain.CapabilityDomain;
const CapabilityType = capability.CapabilityType;
const EcCaps = execution_context.EcCaps;
const EcQueue = scheduler.EcQueue;
const ErasedSlabRef = capability.ErasedSlabRef;
const EventType = execution_context.EventType;
const ExecutionContext = execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const KernelHandle = capability.KernelHandle;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const Word0 = capability.Word0;

// ── Timed recv waiters ───────────────────────────────────────────────
//
// Parallel structure to sched.futex.timed_waiters: a fixed array of EC
// pointers blocked in `recv` with a non-zero timeout. The scheduler
// tick (arch.x64.irq.schedTimerHandler) drives `expireTimedRecvWaiters`
// which dequeues expired ECs from their port's receiver queue, sets
// their syscall return to E_TIMEOUT, and re-schedules them.
//
// 256 slots is more than the spec needs (one EC can hold at most one
// recv-with-timeout in flight; concurrent recv-with-timeout count is
// bounded by core count plus user-space concurrency).
const MAX_TIMED_RECV_WAITERS: usize = 256;
var timed_recv_waiters: [MAX_TIMED_RECV_WAITERS]?*ExecutionContext = blk: {
    var arr: [MAX_TIMED_RECV_WAITERS]?*ExecutionContext = undefined;
    for (&arr) |*slot| slot.* = null;
    break :blk arr;
};
var timed_recv_lock: SpinLock = .{ .class = "port.timed_recv_lock" };

fn addTimedRecvWaiter(ec: *ExecutionContext) bool {
    const irq = timed_recv_lock.lockIrqSave(@src());
    defer timed_recv_lock.unlockIrqRestore(irq);
    for (&timed_recv_waiters) |*slot| {
        if (slot.* == null) {
            slot.* = ec;
            return true;
        }
    }
    return false;
}

fn removeTimedRecvWaiter(ec: *ExecutionContext) void {
    const irq = timed_recv_lock.lockIrqSave(@src());
    defer timed_recv_lock.unlockIrqRestore(irq);
    for (&timed_recv_waiters) |*slot| {
        if (slot.* == ec) {
            slot.* = null;
            return;
        }
    }
}

/// Called from the scheduler tick to expire any recv-blocked ECs whose
/// `recv_deadline_ns` has passed. Spec §[port].recv test 14.
///
/// Phase 1 snapshots expired ECs under `timed_recv_lock`; Phase 2
/// removes each from its port's receiver queue under that port's
/// `_gen_lock`. The split avoids holding `timed_recv_lock` across a
/// Port lock acquisition (lock-order: Port locks may already be held
/// when timed_recv_lock is taken in `addTimedRecvWaiter`).
pub fn expireTimedRecvWaiters() void {
    const now_ns = arch.time.getMonotonicClock().now();

    const Snapshot = struct { ec: *ExecutionContext, deadline: u64 };
    var expired: [MAX_TIMED_RECV_WAITERS]Snapshot = undefined;
    var expired_count: usize = 0;
    {
        const irq = timed_recv_lock.lockIrqSave(@src());
        defer timed_recv_lock.unlockIrqRestore(irq);
        for (&timed_recv_waiters) |*slot| {
            const ec = slot.* orelse continue;
            if (ec.recv_deadline_ns == 0 or now_ns < ec.recv_deadline_ns) continue;
            expired[expired_count] = .{ .ec = ec, .deadline = ec.recv_deadline_ns };
            expired_count += 1;
            slot.* = null;
        }
    }

    for (expired[0..expired_count]) |entry| {
        const ec = entry.ec;
        // Re-check deadline. If a sender wake ran between phases the
        // deadline is now 0; if the EC was woken and made a fresh recv
        // it'd be a different value. Either way this snapshot is stale.
        if (ec.recv_deadline_ns != entry.deadline) continue;

        const port_ref = ec.suspend_port orelse continue;
        const p = port_ref.lock(@src()) catch continue;

        // Remove from the port's receiver queue if still present.
        // (`waiters.remove` is a no-op if the EC was already dequeued
        // by a sender on a different core.)
        const removed = p.waiters.remove(ec);
        if (removed and p.waiters.isEmpty()) p.waiter_kind = .none;
        port_ref.unlock();

        if (!removed) continue;

        // EC has been removed from the wait queue; safe to wake.
        while (ec.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        ec.recv_deadline_ns = 0;
        ec.suspend_port = null;
        ec.event_type = .none;
        // Stash E_TIMEOUT in the syscall return slot. The scheduler's
        // resume path puts vreg 1 back into rax on iretq.
        ec.ctx.regs.rax = @bitCast(errors.E_TIMEOUT);
        ec.state = .ready;
        scheduler.markReady(ec);
    }
}

/// Cap bits in `Capability.word0[48..63]` for port handles.
/// Spec §[port] cap layout.
pub const PortCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    xfer: bool = false,
    recv: bool = false,
    bind: bool = false,
    restart_policy: u1 = 0,
    _reserved: u10 = 0,
};

/// Cap bits in `Capability.word0[48..63]` for reply handles.
/// Spec §[reply] cap layout. `copy` is always 0 by spec.
pub const ReplyCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    xfer: bool = false,
    _reserved: u13 = 0,
};

/// Names which side currently owns `Port.waiters`. A port can never
/// hold both senders and receivers at once: if a sender arrives with
/// receivers queued (or vice versa), the matching pair is consumed
/// before the queue settles. The dequeuer that empties the queue is
/// responsible for resetting this back to `.none`.
pub const WaiterKind = enum {
    /// Queue empty.
    none,
    /// Suspended ECs waiting to be picked up by a `recv`.
    senders,
    /// ECs blocked in `recv` waiting for an event.
    receivers,
};

pub const Port = struct {
    /// Slab generation lock. Validates `SlabRef(Port)` liveness AND
    /// guards every mutable field below.
    _gen_lock: GenLock = .{},

    /// Count of handles to this port that carry `bind` OR `xfer` caps —
    /// the cap set that authorizes putting something onto the port from
    /// the sender side (suspending an EC, attaching capabilities to a
    /// suspension). Each handle contributes at most 1 regardless of how
    /// many qualifying caps it carries; `restrict` that strips the last
    /// qualifying cap from a handle decrements it.
    send_refcount: u32 = 0,

    /// Count of handles to this port that carry the `recv` cap. Same
    /// per-handle accounting as `send_refcount`.
    recv_refcount: u32 = 0,

    /// Number of kernel-held event routes (bind_event_route bindings)
    /// whose destination is this port. Keeps receivers valid even when
    /// `send_refcount` has dropped to 0 — fault and pmu_overflow
    /// deliveries through routes are still possible until this also
    /// hits 0.
    event_route_count: u32 = 0,

    /// Wait queue, holding either suspended senders OR blocked receivers
    /// — never both. `waiter_kind` names which.
    waiters: EcQueue = .{},

    /// Which side owns `waiters`. `.none` iff the queue is empty.
    waiter_kind: WaiterKind = .none,
};

// Layout asserts for the L4 IPC fast path. The current Zig
// `suspendFast` reaches `Port` through normal field access, so these
// guard against drift that would silently break a future Phase 4 asm
// rendezvous (which references `_gen_lock`, `waiters`, and
// `waiter_kind` as immediate displacements off `*Port`).
comptime {
    if (@offsetOf(Port, "waiter_kind") <= @offsetOf(Port, "waiters")) {
        @compileError("Port.waiter_kind must follow Port.waiters (asm fast path)");
    }
    if (@offsetOf(Port, "_gen_lock") >= @offsetOf(Port, "waiters")) {
        @compileError("Port._gen_lock must precede Port.waiters (asm fast path)");
    }
}

pub const Allocator = SecureSlab(Port, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

/// Bit positions used to encode the recv-side syscall return word per
/// §[event_state]: pair_count[12-19], tstart[20-31], reply_handle_id
/// [32-43], event_type[44-48].
const PAIR_COUNT_SHIFT: u6 = 12;
const TSTART_SHIFT: u6 = 20;
const REPLY_HANDLE_SHIFT: u6 = 32;
const EVENT_TYPE_SHIFT: u6 = 44;

// ── External API ─────────────────────────────────────────────────────

/// `create_port` syscall handler. Spec §[port].create_port.
///
/// Caller-side cap-ceiling and `crpt` checks are done in syscall/port.zig
/// before reaching here; this layer mints the slab and the handle.
pub fn createPort(caller: *ExecutionContext, caps: u64) i64 {
    const port_caps: PortCaps = @bitCast(@as(u16, @truncate(caps)));

    const cd_ref = caller.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;
    defer cd_ref.unlock();

    if (cd.free_count == 0) return errors.E_FULL;

    const port = allocPort() catch return errors.E_NOMEM;

    onHandleAcquire(port, @bitCast(port_caps));

    const obj_ref: ErasedSlabRef = .{
        .ptr = port,
        .gen = @intCast(port._gen_lock.currentGen()),
    };
    const port_caps_word: u16 = @bitCast(port_caps);
    const slot = capability_domain.mintHandle(
        cd,
        obj_ref,
        .port,
        port_caps_word,
        0,
        0,
    ) catch {
        _ = onHandleRelease(port, @bitCast(port_caps));
        return errors.E_FULL;
    };
    // Spec §[error_codes] / §[capabilities]: pack Word0 so the
    // returned value carries the type tag in bits 12..15 and never
    // collides with the small-positive error range 1..15.
    return @intCast(Word0.pack(slot, .port, port_caps_word));
}

/// L4 IPC fast path (Phase 2 + 3 in Zig). Resolves `target` and `port`
/// handles inline against `caller.domain`, validates `susp` and `bind`
/// caps, and — if a receiver is queued on the port — performs the
/// rendezvous via `suspendOnPort` without going back through the slow
/// path's argument-slice + dispatch-switch.
///
/// Returns `null` to signal predicate miss; caller must fall through to
/// the slow path (which performs identical state mutations on success
/// and surfaces the appropriate error code on validation failures, so
/// the fall-through is observably equivalent to running the fast path
/// to completion).
///
/// Predicate (must ALL hold; returns null otherwise):
///   - `target` and `port` resolve cleanly in the caller's `user_table`
///     to the expected types (`execution_context`, `port`).
///   - The target EC is the caller itself — self-suspend, the dominant
///     test pattern. Cross-EC suspend stays on the slow path because it
///     needs an extra EC `_gen_lock` round trip and a separate state
///     check that would dilute the fast path's branch budget.
///   - The target handle has the `susp` cap and the port handle has the
///     `bind` cap.
///   - The caller is not a vCPU.
///   - The port has at least one queued receiver
///     (`waiter_kind == .receivers`).
///
/// On predicate match the result is identical to what `suspendEc` would
/// have produced via `suspendOnPort` → `rendezvousWithReceiver`: caller
/// transitions to `.suspended_on_port`, the highest-priority receiver
/// is dequeued and made `.ready` with the §[event_state] vregs filled,
/// and `current_ec` is cleared on this core so the syscall epilogue
/// dispatches the next ready EC.
///
/// Lock order: CD → Port (canonical, matches §[delete] release path).
/// CD is dropped before Port is taken, so `suspendOnPort` →
/// `rendezvousWithReceiver` can acquire the receiver's CD without
/// inverting the order.
pub fn suspendFast(caller: *ExecutionContext, target: u64, port: u64) ?i64 {
    if (target & ~capability.HANDLE_ARG_MASK != 0) return null;
    if (port & ~capability.HANDLE_ARG_MASK != 0) return null;
    if (caller.vm != null) return null;

    const cd_ref = caller.domain;
    const cd = cd_ref.lock(@src()) catch return null;

    const target_slot: u12 = @truncate(target);
    const port_slot: u12 = @truncate(port);

    const target_entry = capability.resolveHandleOnDomain(cd, target_slot, .execution_context) orelse {
        cd_ref.unlock();
        return null;
    };
    const port_entry = capability.resolveHandleOnDomain(cd, port_slot, .port) orelse {
        cd_ref.unlock();
        return null;
    };

    // Self-suspend predicate: target EC must be the caller itself. The
    // typed ref's ptr is the underlying object pointer; when it points
    // back at `caller` we can skip the cross-EC lock dance entirely.
    const target_ref = capability.typedRef(ExecutionContext, target_entry.*) orelse {
        cd_ref.unlock();
        return null;
    };
    if (target_ref.ptr != caller) {
        cd_ref.unlock();
        return null;
    }

    const ec_caps: EcCaps = @bitCast(Word0.caps(cd.user_table[target_slot].word0));
    if (!ec_caps.susp) {
        cd_ref.unlock();
        return null;
    }
    const port_caps: PortCaps = @bitCast(Word0.caps(cd.user_table[port_slot].word0));
    if (!port_caps.bind) {
        cd_ref.unlock();
        return null;
    }

    const port_ref = capability.typedRef(Port, port_entry.*) orelse {
        cd_ref.unlock();
        return null;
    };
    cd_ref.unlock();

    const p = port_ref.lock(@src()) catch return null;

    // Only commit to the fast path when there's a receiver to hand off
    // to. The no-receiver branch (sender parks on the port) requires
    // the same state mutations but produces no observable speedup over
    // the slow path, so let the slow path own it — keeps this function
    // a single tight predicate→rendezvous path.
    if (p.waiter_kind != .receivers) {
        port_ref.unlock();
        return null;
    }

    // `suspendOnPort` requires the port lock held on entry; it releases
    // the lock either directly (no-receiver path) or transitively via
    // `rendezvousWithReceiver` (success path, drops port before locking
    // receiver's CD to honor CD → Port).
    return execution_context.suspendOnPort(caller, p, .suspension, 0, 0, ec_caps.write);
}

/// `suspend` syscall handler. Spec §[port].suspend.
///
/// Slow-path mirror of arch/x64/interrupts.zig fast suspend: on success
/// the caller's EC ends up either suspended on `port` (if no receiver
/// waiting) or still running with the receiver dequeued and event state
/// delivered. State produced here MUST match what the fast path produces
/// so the two are interchangeable.
pub fn suspendEc(caller: *ExecutionContext, target: u64, port: u64) i64 {
    const cd_ref = caller.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;

    const target_slot: u12 = @truncate(target);
    const port_slot: u12 = @truncate(port);

    const target_entry = capability.resolveHandleOnDomain(cd, target_slot, .execution_context) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };
    const port_entry = capability.resolveHandleOnDomain(cd, port_slot, .port) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };

    const ec_caps: EcCaps = @bitCast(Word0.caps(cd.user_table[target_slot].word0));
    if (!ec_caps.susp) {
        cd_ref.unlock();
        return errors.E_PERM;
    }

    const target_ref = capability.typedRef(ExecutionContext, target_entry.*) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };
    const port_ref = capability.typedRef(Port, port_entry.*) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };
    cd_ref.unlock();

    const target_ec = target_ref.lock(@src()) catch return errors.E_BADCAP;
    if (target_ec.vm != null) {
        target_ref.unlock();
        return errors.E_INVAL;
    }
    if (target_ec.state == .suspended_on_port) {
        target_ref.unlock();
        return errors.E_INVAL;
    }
    target_ref.unlock();

    const p = port_ref.lock(@src()) catch return errors.E_BADCAP;
    // `suspendOnPort` releases the port lock before returning (directly
    // on the no-receiver path, transitively via `rendezvousWithReceiver`
    // on the success path) so we MUST NOT add `defer port_ref.unlock()`.

    // Snapshot the originating EC handle's `write` cap so reply-time
    // can decide whether receiver mutations apply (Spec §[reply] tests
    // 05/06). The caps were captured into `ec_caps` above under the
    // domain lock.
    return execution_context.suspendOnPort(target_ec, p, .suspension, 0, 0, ec_caps.write);
}

/// `recv` syscall handler. Spec §[port].recv.
///
/// Slow path: if a sender is queued, pair off, mint a reply handle in
/// the caller's domain, deliver event state via vregs, and return. If no
/// sender is queued and the port has bind holders or routes, the caller
/// suspends as a receiver; otherwise returns E_CLOSED.
///
/// Lock order: caller's CD `_gen_lock` is acquired first, held for the
/// duration of the Port lock acquisition + port-side work, and only
/// dropped after `deliverEvent` finishes (which needs CD held to mint
/// the reply slot). The Port lock is released before `deliverEvent` runs
/// so the canonical CD → Port order is never inverted — see the lock-
/// order note on `deliverEvent`.
pub fn recv(caller: *ExecutionContext, port: u64, timeout_ns: u64) i64 {
    const cd_ref = caller.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;
    defer cd_ref.unlock();

    const port_slot: u12 = @truncate(port);
    const port_entry = capability.resolveHandleOnDomain(cd, port_slot, .port) orelse
        return errors.E_BADCAP;
    const port_ref = capability.typedRef(Port, port_entry.*) orelse
        return errors.E_BADCAP;

    const p = port_ref.lock(@src()) catch return errors.E_BADCAP;

    if (p.waiter_kind == .senders) {
        const sender = popHighestPrioritySender(p) orelse {
            port_ref.unlock();
            return errors.E_CLOSED;
        };
        // Drop the Port lock before deliverEvent — it needs receiver-CD
        // (the caller's CD, already held by us). Holding both would
        // re-introduce the Port → CD inversion.
        const evt_type = sender.event_type;
        const evt_sub = sender.event_subcode;
        const evt_addr = sender.event_addr;
        port_ref.unlock();
        return deliverEvent(sender, caller, cd, evt_type, evt_sub, evt_addr, 0);
    }

    // No sender ready. Spec §[port].recv test 04: if the port has no
    // bind-cap holders, no event_routes, and no events queued, return
    // E_CLOSED rather than blocking forever.
    if (p.send_refcount == 0 and p.event_route_count == 0) {
        port_ref.unlock();
        return errors.E_CLOSED;
    }

    enqueueReceiver(p, caller);
    caller.event_type = .none;
    caller.suspend_port = SlabRef(Port).init(p, p._gen_lock.currentGen());
    caller.state = .suspended_on_port;
    caller.pending_reply_holder = null;
    caller.on_cpu.store(false, .release);

    // Timed recv — register before dropping the port lock so the wakeup
    // path can find us. Spec §[port].recv test 14.
    if (timeout_ns != 0) {
        const now_ns = arch.time.getMonotonicClock().now();
        caller.recv_deadline_ns = now_ns + timeout_ns;
        _ = addTimedRecvWaiter(caller);
    }

    port_ref.unlock();

    const core_id = arch.smp.coreID();
    if (scheduler.core_states[core_id].current_ec == caller) {
        scheduler.core_states[core_id].current_ec = null;
    }
    return 0;
}

/// `reply` syscall handler. Spec §[reply].reply.
pub fn reply(caller: *ExecutionContext, reply_handle: u64) i64 {
    const cd_ref = caller.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;

    const slot: u12 = @truncate(reply_handle);
    const entry = capability.resolveHandleOnDomain(cd, slot, .reply) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };

    const sender_ref = capability.typedRef(ExecutionContext, entry.*) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };

    // Snapshot the caps on the reply handle and clear the slot under
    // the domain lock so a concurrent delete cannot race the resume.
    const reply_caps: ReplyCaps = @bitCast(Word0.caps(cd.user_table[slot].word0));
    _ = reply_caps;

    capability.clearAndFreeSlot(cd, slot, entry);

    cd_ref.unlock();

    const sender = sender_ref.lock(@src()) catch return errors.E_TERM;
    defer sender_ref.unlock();

    consumeReply(entry, sender);
    return 0;
}

/// `reply_transfer` syscall handler. Spec §[reply].reply_transfer.
pub fn replyTransfer(caller: *ExecutionContext, reply_handle: u64, n: u8) i64 {
    _ = n;
    return reply(caller, reply_handle);
}

/// `bind_event_route` syscall handler. Spec §[event_route].bind_event_route.
///
/// Top-level entry kept for symmetry with the syscall surface; the
/// real per-call work happens in syscall/event_route.zig which routes
/// into `installEventRoute` below after locking caller, target EC, and
/// destination port.
pub fn bindEventRoute(caller: *ExecutionContext, target: u64, event_type_raw: u64, port: u64) i64 {
    _ = caller;
    _ = target;
    _ = event_type_raw;
    _ = port;
    return errors.E_INVAL;
}

/// `clear_event_route` syscall handler. Spec §[event_route].clear_event_route.
pub fn clearEventRoute(caller: *ExecutionContext, target: u64, event_type_raw: u64) i64 {
    _ = caller;
    _ = target;
    _ = event_type_raw;
    return errors.E_INVAL;
}

/// Install `port` as `ec.event_routes[slot_idx]`, replacing any prior
/// binding. Caller has already locked `ec` and `port` and validated caps.
/// Bumps `port.event_route_count` and decrements the prior port's
/// `event_route_count` (if any) under their respective `_gen_lock`s.
pub fn installEventRoute(ec: *ExecutionContext, port: *Port, slot_idx: u8) i64 {
    if (ec.event_routes[slot_idx]) |prior_ref| {
        // Caller already holds `port._gen_lock` and `ec._gen_lock`. The
        // prior port is a different slab slot; reach in to dec its route
        // count without re-acquiring `port`'s lock. If the dec drove the
        // prior port to teardown, `destroyLocked` already released its
        // lock — skip the SlabRef-side unlock.
        const prior = prior_ref.lock(@src()) catch null;
        if (prior) |pr| {
            const destroyed = decEventRouteCount(pr);
            if (!destroyed) prior_ref.unlock();
        }
    }
    incEventRouteCount(port);
    ec.event_routes[slot_idx] = SlabRef(Port).init(port, port._gen_lock.currentGen());
    return 0;
}

/// Remove the binding at `ec.event_routes[slot_idx]`. Caller has already
/// locked `ec` and validated `unbind` cap and that the slot is non-null.
/// Decrements the bound port's `event_route_count` under its `_gen_lock`,
/// triggering `propagateClosedToReceivers` if the port now has no
/// remaining holders.
pub fn removeEventRoute(ec: *ExecutionContext, slot_idx: u8) i64 {
    const prior_ref = ec.event_routes[slot_idx] orelse return errors.E_NOENT;
    const prior = prior_ref.lock(@src()) catch {
        ec.event_routes[slot_idx] = null;
        return 0;
    };
    const destroyed = decEventRouteCount(prior);
    if (!destroyed) prior_ref.unlock();
    ec.event_routes[slot_idx] = null;
    return 0;
}

// ── Kernel-internal event firing (called from arch fault/PMU paths) ──

/// Common dispatch for `fire*`. Looks up `ec.event_routes[event_type]`;
/// if bound, suspends `ec` on the port. Returns true iff the suspend was
/// performed; false leaves the caller to apply the no-route fallback.
fn fireRouted(
    ec: *ExecutionContext,
    event: EventType,
    subcode: u8,
    addr: u64,
) bool {
    const slot_idx = execution_context.eventRouteSlot(event) orelse return false;
    const route_ref = ec.event_routes[slot_idx] orelse return false;
    const port_ptr = route_ref.lock(@src()) catch return false;
    // `suspendOnPort` is responsible for releasing `port_ptr._gen_lock`
    // (it must drop Port before any receiver-CD acquisition to honor the
    // canonical CD → Port order). We must NOT also `defer route_ref.unlock()`.

    // A route whose port has lost every bind-cap holder AND has no other
    // routes pointing at it survives only on the route's own increment.
    // Receivers are still allowed to dequeue from such a port, so honor
    // the route here — the EC will sit suspended until either a recv
    // arrives or the route itself is cleared.
    // The originating EC handle here is the one that called
    // `bind_event_route` (Spec §[reply] originating-handle table). Its
    // write-cap snapshot is not yet plumbed through to this path; until
    // event_route bookkeeping records that snapshot at bind time the
    // safe default is to discard receiver mutations on reply (§[reply]
    // test 06's no-write-cap branch).
    _ = execution_context.suspendOnPort(ec, port_ptr, event, subcode, addr, false);
    return true;
}

/// Fire a memory_fault event for `ec`. Looks up `ec.event_routes[0]`;
/// if bound, suspends `ec` on the port; else applies no-route fallback
/// (restart domain or destroy). Spec §[event_route].
pub fn fireMemoryFault(ec: *ExecutionContext, subcode: u8, fault_addr: u64) void {
    if (fireRouted(ec, .memory_fault, subcode, fault_addr)) return;

    arch.boot.printRaw("[fault] memory_fault no-route fallback (panic)\n");
    @panic("memory_fault with no event_route — restartDomain/releaseSelf are stubbed; cannot recover");
}

/// Fire a thread_fault event. Fallback on no route: terminate EC.
pub fn fireThreadFault(ec: *ExecutionContext, subcode: u8, payload: u64) void {
    if (fireRouted(ec, .thread_fault, subcode, payload)) return;
    // No-route fallback: terminate the EC. The terminate path destroys
    // the slab slot, which gen-bumps every outstanding handle to E_TERM.
    _ = execution_context.terminate(ec, 0);
}

/// Fire a breakpoint event. Fallback: drop, advance past trap, resume.
pub fn fireBreakpoint(ec: *ExecutionContext, subcode: u8) void {
    if (fireRouted(ec, .breakpoint, subcode, 0)) return;
    // No-route fallback: drop the event and let `ec` resume. The
    // arch-specific helper that advances past the trap instruction
    // lives in arch.dispatch.cpu — until that one-byte INT3 advance is
    // wired through dispatch, leave the EC at the trapping RIP and
    // rely on the arch entry path to continue.
}

/// Fire a pmu_overflow event. Fallback: drop, EC continues running.
pub fn firePmuOverflow(ec: *ExecutionContext, counter_idx: u64) void {
    const subcode: u8 = @truncate(counter_idx);
    if (fireRouted(ec, .pmu_overflow, subcode, counter_idx)) return;
    // No-route fallback: silently drop. The EC keeps running and the
    // counter has already been re-armed by the arch ISR.
}

/// Fire a vm_exit event for a vCPU EC. Routes to `ec.exit_port`
/// directly (not through `event_routes`). Spec §[vm_exit_state].
pub fn fireVmExit(ec: *ExecutionContext, subcode: u8, payload: [3]u64) void {
    const exit_port_ref = ec.exit_port orelse return;
    const port_ptr = exit_port_ref.lock(@src()) catch return;
    // `suspendOnPort` releases the port lock before returning — see its
    // contract. Do NOT add `defer exit_port_ref.unlock()` here.

    // The originating EC handle for vm_exit is the vCPU EC handle held
    // by the VMM. Its write-cap snapshot drives whether reply applies
    // receiver mutations. The lookup that captures that bit per-vCPU
    // is part of the VMM-owned exit pipeline; until it lands, default
    // to allowing applies (the common case for VMM resume) so the
    // exit→reply→resume cycle remains observable end-to-end.
    _ = execution_context.suspendOnPort(ec, port_ptr, .vm_exit, subcode, payload[0], true);
}

// ── Internal API ─────────────────────────────────────────────────────

/// Allocate a Port. Initial counters are caps-driven by the caller.
fn allocPort() !*Port {
    const ref = try slab_instance.create();
    const p = ref.ptr;
    p.send_refcount = 0;
    p.recv_refcount = 0;
    p.event_route_count = 0;
    p.waiters = .{};
    p.waiter_kind = .none;
    return p;
}

/// Final teardown — caller observed all three counters at zero under
/// `_gen_lock`. Frees the slab slot.
fn destroyPort(p: *Port) void {
    // Lock is held by the decrementer that drove counters to 0; release
    // and gen-bump in one shot via `destroyLocked`.
    const gen = p._gen_lock.currentGen();
    slab_instance.destroyLocked(p, gen);
}

/// True iff send_refcount + recv_refcount + event_route_count == 0.
fn shouldDestroy(p: *const Port) bool {
    return p.send_refcount == 0 and p.recv_refcount == 0 and p.event_route_count == 0;
}

/// Refcount adjusters — each `dec*` checks for teardown / E_CLOSED
/// propagation on transition to 0. All under `_gen_lock`. Each `dec*`
/// returns true iff it drove the port to teardown — the caller uses the
/// flag to skip a redundant unlock (`destroyPort` releases the lock as
/// part of the gen bump in `destroyLocked`).
fn incSendRefcount(p: *Port) void {
    p.send_refcount += 1;
}
fn decSendRefcount(p: *Port) bool {
    std.debug.assert(p.send_refcount > 0);
    p.send_refcount -= 1;
    if (p.send_refcount == 0 and p.event_route_count == 0) {
        propagateClosedToReceivers(p);
    }
    if (shouldDestroy(p)) {
        destroyPort(p);
        return true;
    }
    return false;
}
fn incRecvRefcount(p: *Port) void {
    p.recv_refcount += 1;
}
fn decRecvRefcount(p: *Port) bool {
    std.debug.assert(p.recv_refcount > 0);
    p.recv_refcount -= 1;
    if (p.recv_refcount == 0) propagateClosedToSenders(p);
    if (shouldDestroy(p)) {
        destroyPort(p);
        return true;
    }
    return false;
}
fn incEventRouteCount(p: *Port) void {
    p.event_route_count += 1;
}
fn decEventRouteCount(p: *Port) bool {
    std.debug.assert(p.event_route_count > 0);
    p.event_route_count -= 1;
    if (p.send_refcount == 0 and p.event_route_count == 0) {
        propagateClosedToReceivers(p);
    }
    if (shouldDestroy(p)) {
        destroyPort(p);
        return true;
    }
    return false;
}

/// Aggregate handle-cap bookkeeping. Called from caps copy/delete/
/// restrict to translate cap-bit edge transitions into refcount calls.
fn onHandleAcquire(p: *Port, caps: u16) void {
    const c: PortCaps = @bitCast(caps);
    if (c.bind or c.xfer) incSendRefcount(p);
    if (c.recv) incRecvRefcount(p);
}

/// Returns true iff the release drove the port to teardown — caller
/// must skip the standard unlock since `destroyPort` released the lock
/// via `destroyLocked`.
fn onHandleRelease(p: *Port, caps: u16) bool {
    const c: PortCaps = @bitCast(caps);
    var destroyed = false;
    if (c.bind or c.xfer) destroyed = decSendRefcount(p) or destroyed;
    if (c.recv) destroyed = decRecvRefcount(p) or destroyed;
    return destroyed;
}

/// Public release-handle entry point invoked from the cross-cutting
/// `caps.capability.delete` path. Wraps `onHandleRelease`.
pub fn releaseHandle(p: *Port, caps: u16) void {
    p._gen_lock.lock(@src());
    const destroyed = onHandleRelease(p, caps);
    // `decSendRefcount`/`decRecvRefcount` already released the lock via
    // `destroyLocked` on the teardown transition; only unlock when no
    // decrement drove the port through teardown.
    if (!destroyed) p._gen_lock.unlock();
}

fn onHandleRestrict(p: *Port, old_caps: u16, new_caps: u16) bool {
    const old_c: PortCaps = @bitCast(old_caps);
    const new_c: PortCaps = @bitCast(new_caps);
    const old_send = old_c.bind or old_c.xfer;
    const new_send = new_c.bind or new_c.xfer;
    var destroyed = false;
    if (old_send and !new_send) destroyed = decSendRefcount(p) or destroyed;
    if (old_c.recv and !new_c.recv) destroyed = decRecvRefcount(p) or destroyed;
    return destroyed;
}

/// Wait queue ops — assert empty or matching kind, transition kind
/// on (en)queue, reset to .none when drained.
fn enqueueSender(p: *Port, sender: *ExecutionContext) void {
    std.debug.assert(p.waiter_kind != .receivers);
    p.waiters.enqueue(sender);
    p.waiter_kind = .senders;
}
fn enqueueReceiver(p: *Port, receiver: *ExecutionContext) void {
    std.debug.assert(p.waiter_kind != .senders);
    p.waiters.enqueue(receiver);
    p.waiter_kind = .receivers;
}
fn popHighestPrioritySender(p: *Port) ?*ExecutionContext {
    if (p.waiter_kind != .senders) return null;
    const ec = p.waiters.dequeue() orelse return null;
    if (p.waiters.isEmpty()) p.waiter_kind = .none;
    return ec;
}
fn popHighestPriorityReceiver(p: *Port) ?*ExecutionContext {
    if (p.waiter_kind != .receivers) return null;
    const ec = p.waiters.dequeue() orelse return null;
    if (p.waiters.isEmpty()) p.waiter_kind = .none;
    return ec;
}

/// Rendezvous + delivery — called once a (sender, receiver) pair is
/// identified. Mints a reply handle in receiver's domain, processes
/// attachments, writes event-state vregs, transitions states.
///
/// Slow-path mirror of arch/x64/interrupts.zig Phase 4: the syscall
/// return word and event-state vregs written here MUST match what the
/// fast path produces so the two are interchangeable.
///
/// LOCK ORDER: Caller MUST already hold `dom` (receiver's CD `_gen_lock`)
/// AND MUST NOT hold any Port `_gen_lock`. Canonical order across the
/// kernel is `CapabilityDomain` → `Port`; the matching `delete` path
/// takes CD then dispatches to `port.releaseHandle` which takes Port,
/// so this side must finish all Port-held work and drop Port BEFORE
/// reaching here. Holding Port across the CD acquisition done by the
/// previous version of this function created an AB-BA cycle observed
/// by lockdep at port.zig:613 vs port.zig:552.
fn deliverEvent(
    sender: *ExecutionContext,
    receiver: *ExecutionContext,
    dom: *CapabilityDomain,
    event_type: EventType,
    subcode: u8,
    event_addr: u64,
    pair_count: u8,
) i64 {
    const xfer_allowed = pair_count > 0;
    const reply_slot = mintReply(dom, sender, xfer_allowed) catch return errors.E_FULL;

    // Compose §[event_state] syscall return word: pair_count, tstart,
    // reply_handle_id, event_type. tstart only meaningful when pair_count
    // > 0; the fast path leaves it 0 in the no-attachment case so this
    // mirror does the same.
    const ret_word: u64 =
        (@as(u64, pair_count) << PAIR_COUNT_SHIFT) |
        (@as(u64, reply_slot) << REPLY_HANDLE_SHIFT) |
        (@as(u64, @intFromEnum(event_type)) << EVENT_TYPE_SHIFT);

    // §[event_state] vreg 2 = sub-code (sender-suspend metadata),
    // vregs 3 and 4 = sender's GPR-backed vregs snapshotted at suspend
    // time (Spec §[event_state] vregs 1..13 are the suspending EC's
    // GPRs). For suspension events triggered by `suspend(target, port)`
    // both `subcode` and `event_addr` are 0; the sender's `event_vreg3`
    // / `event_vreg4` carry the userspace payload. For fault / vm_exit
    // events the firing site supplies `subcode` and `event_addr` for
    // vreg 2 / vreg 3, and per-spec vreg 3 must reflect the suspended
    // EC's rdx (x2) — the firing-site `event_addr` and the EC's vreg 3
    // are different concepts that today share the same physical
    // register because we have not yet relocated event_addr to a higher
    // vreg slot. The sender snapshot wins per spec §[event_state] —
    // event-specific u64 payloads must move to vreg 19+ (x86-64) /
    // vreg 36+ (aarch64) when those tests come online.
    const target_ctx = receiver.iret_frame orelse receiver.ctx;
    arch.syscall.setSyscallReturn(target_ctx, ret_word);
    arch.syscall.setEventSubcode(target_ctx, subcode);
    _ = event_addr;
    arch.syscall.setEventAddr(target_ctx, sender.event_vreg3);
    arch.syscall.setEventVreg4(target_ctx, sender.event_vreg4);
    arch.syscall.setEventVreg5(target_ctx, sender.event_vreg5);

    // Return the composed `ret_word` as i64 so the recv-fast-path
    // caller (sender already waiting at recv time) can propagate it
    // through `syscallDispatch`'s `r.rax = ret` epilogue. Without this
    // the receiver's saved rax would land as the dispatch's i64 return
    // (0 here) and clobber the `setSyscallReturn` write above. The
    // rendezvous path discards this return and relies on the direct
    // setSyscallReturn write since its receiver is asleep and never
    // re-enters syscallDispatch's epilogue.
    return @bitCast(ret_word);
}

/// Sender-side rendezvous with a waiting receiver. Caller is the
/// suspended sender EC (state already set to `.suspended_on_port` by
/// the suspendOnPort path); we dequeue the highest-priority waiting
/// receiver, mint a reply handle in the receiver's domain, write the
/// event-state syscall return into the receiver's iret frame, and
/// enqueue the receiver as ready.
///
/// Caller MUST hold `p._gen_lock`. On a successful match (`true`
/// returned) the function RELEASES that Port lock before acquiring the
/// receiver's CD lock — canonical kernel order is CD → Port and Port
/// must be dropped before deliverEvent reaches mintReply. Callers must
/// therefore not also unlock `p` themselves on the success path.
/// Returns `false` (with `p._gen_lock` still held) if no receiver was
/// eligible — the caller resumes the slow-path enqueue.
pub fn rendezvousWithReceiver(
    sender: *ExecutionContext,
    p: *Port,
    event_type: EventType,
    subcode: u8,
    event_addr: u64,
) bool {
    const receiver = popHighestPriorityReceiver(p) orelse return false;
    receiver.event_type = .none;
    receiver.suspend_port = null;

    // Cancel any pending recv-with-timeout deadline before delivery.
    // Setting deadline to 0 also makes a stale-snapshot phase-2 expiry
    // skip this EC.
    if (receiver.recv_deadline_ns != 0) {
        receiver.recv_deadline_ns = 0;
        removeTimedRecvWaiter(receiver);
    }

    // Snapshot receiver's CD ref under the port lock, then drop the
    // port lock before acquiring the CD lock. The receiver is no
    // longer queued on the port; its slab slot stays alive while
    // state is `.suspended_on_port`. Holding port across the CD
    // acquisition would re-introduce the AB-BA cycle that lockdep
    // catches against the `delete → releaseHandle` path.
    const receiver_dom_ref = receiver.domain;
    p._gen_lock.unlock();

    const dom = receiver_dom_ref.lock(@src()) catch {
        // Receiver's CD was torn down between the pop and our lock —
        // the receiver itself is doomed via the same teardown. Drop
        // the rendezvous; the sender remains parked (state already set
        // by suspendOnPort) and will be woken by E_CLOSED when the
        // port's last refcount drops, or be reaped at sender teardown.
        return true;
    };
    defer receiver_dom_ref.unlock();

    _ = deliverEvent(sender, receiver, dom, event_type, subcode, event_addr, 0);
    receiver.state = .ready;
    scheduler.markReady(receiver);
    return true;
}

/// Mint a reply handle in `receiver_domain`'s table pointing at the
/// suspended `sender` EC. Sets `sender.pending_reply_holder` back-pointer.
fn mintReply(receiver_domain: *CapabilityDomain, sender: *ExecutionContext, xfer: bool) !u12 {
    const reply_caps: ReplyCaps = .{
        .move = true,
        .copy = false,
        .xfer = xfer,
    };

    const obj_ref: ErasedSlabRef = .{
        .ptr = sender,
        .gen = @intCast(sender._gen_lock.currentGen()),
    };
    const slot = try capability_domain.mintHandle(
        receiver_domain,
        obj_ref,
        .reply,
        @bitCast(reply_caps),
        0,
        0,
    );

    sender.pending_reply_holder = &receiver_domain.kernel_table[slot];
    return slot;
}

/// Resume the sender via the reply path, applying receiver's GPR
/// modifications (gated by originating EC handle's `write` cap).
/// Spec §[reply] tests 05/06.
fn consumeReply(holder: *KernelHandle, sender: *ExecutionContext) void {
    _ = holder;
    // The write-cap snapshot was stamped onto `sender` at suspend time
    // (see `suspendOnPort`); any receiver-side modifications to the
    // event-state vregs commit to the sender's saved iret frame iff
    // that bit was set.
    execution_context.resumeFromReply(sender, sender.originating_write_cap);
}

/// Resume the suspended sender with `E_ABANDONED` — the path invoked
/// when `delete` consumes a reply handle without resuming.
fn resumeWithAbandoned(sender: *ExecutionContext) void {
    if (sender.iret_frame) |frame| {
        arch.syscall.setSyscallReturn(frame, @bitCast(errors.E_ABANDONED));
    } else {
        arch.syscall.setSyscallReturn(sender.ctx, @bitCast(errors.E_ABANDONED));
    }
    execution_context.resumeFromReply(sender, false);
}

/// On send_refcount → 0 with event_route_count == 0: wake all blocked
/// receivers with E_CLOSED.
fn propagateClosedToReceivers(p: *Port) void {
    if (p.waiter_kind != .receivers) return;
    while (p.waiters.dequeue()) |waiter| {
        if (waiter.iret_frame) |frame| {
            arch.syscall.setSyscallReturn(frame, @bitCast(errors.E_CLOSED));
        } else {
            arch.syscall.setSyscallReturn(waiter.ctx, @bitCast(errors.E_CLOSED));
        }
        waiter.suspend_port = null;
        waiter.state = .ready;
        scheduler.markReady(waiter);
    }
    p.waiter_kind = .none;
}

/// On recv_refcount → 0: wake all suspended senders with E_CLOSED;
/// drop their pre-validated attachments without effect.
fn propagateClosedToSenders(p: *Port) void {
    if (p.waiter_kind != .senders) return;
    while (p.waiters.dequeue()) |sender| {
        if (sender.iret_frame) |frame| {
            arch.syscall.setSyscallReturn(frame, @bitCast(errors.E_CLOSED));
        } else {
            arch.syscall.setSyscallReturn(sender.ctx, @bitCast(errors.E_CLOSED));
        }
        sender.suspend_port = null;
        sender.event_type = .none;
        sender.event_subcode = 0;
        sender.event_addr = 0;
        sender.originating_write_cap = false;
        sender.state = .ready;
        scheduler.markReady(sender);
    }
    p.waiter_kind = .none;
}
