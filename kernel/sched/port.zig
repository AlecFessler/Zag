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
const Word0 = capability.Word0;

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

pub const Allocator = SecureSlab(Port, 256);
pub var slab_instance: Allocator = undefined;

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
    const slot = capability_domain.mintHandle(
        cd,
        obj_ref,
        .port,
        @bitCast(port_caps),
        0,
        0,
    ) catch {
        onHandleRelease(port, @bitCast(port_caps));
        return errors.E_FULL;
    };
    return @intCast(slot);
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
    defer port_ref.unlock();

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
pub fn recv(caller: *ExecutionContext, port: u64) i64 {
    const cd_ref = caller.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;

    const port_slot: u12 = @truncate(port);
    const port_entry = capability.resolveHandleOnDomain(cd, port_slot, .port) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };
    const port_ref = capability.typedRef(Port, port_entry.*) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };
    cd_ref.unlock();

    const p = port_ref.lock(@src()) catch return errors.E_BADCAP;
    defer port_ref.unlock();

    if (p.waiter_kind == .senders) {
        const sender = popHighestPrioritySender(p) orelse return errors.E_CLOSED;
        return deliverEvent(sender, caller, p, sender.event_type, sender.event_subcode, sender.event_addr, 0);
    }

    // No sender ready. Spec §[port].recv test 04: if the port has no
    // bind-cap holders, no event_routes, and no events queued, return
    // E_CLOSED rather than blocking forever.
    if (p.send_refcount == 0 and p.event_route_count == 0) return errors.E_CLOSED;

    enqueueReceiver(p, caller);
    caller.event_type = .none;
    caller.suspend_port = SlabRef(Port).init(p, p._gen_lock.currentGen());
    caller.state = .suspended_on_port;
    caller.pending_reply_holder = null;
    caller.on_cpu.store(false, .release);

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

    cd.user_table[slot] = .{ .word0 = 0, .field0 = 0, .field1 = 0 };
    entry.ref = .{};
    entry.metadata = capability.encodeFreeNext(cd.free_head);
    cd.free_head = @as(u16, slot);
    cd.free_count += 1;

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
    defer route_ref.unlock();

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

    // No-route fallback: restart the EC's domain if its self-handle has
    // the `restart` cap, otherwise destroy. Both paths terminate the
    // currently-faulting EC so it doesn't get re-dispatched.
    const dom_ref = ec.domain;
    const dom = dom_ref.lock(@src()) catch return;
    const self_caps_word = Word0.caps(dom.user_table[0].word0);
    const self_caps: capability_domain.CapabilityDomainCaps = @bitCast(self_caps_word);
    dom_ref.unlock();

    if (self_caps.restart) {
        _ = capability_domain.restartDomain(dom);
    } else {
        capability_domain.releaseSelf(dom);
    }
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
    defer exit_port_ref.unlock();
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
fn deliverEvent(
    sender: *ExecutionContext,
    receiver: *ExecutionContext,
    p: *Port,
    event_type: EventType,
    subcode: u8,
    event_addr: u64,
    pair_count: u8,
) i64 {
    const dom_ref = receiver.domain;
    const dom = dom_ref.lock(@src()) catch return errors.E_BADCAP;
    defer dom_ref.unlock();

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

    // §[event_state] vreg 2 = sub-code, vreg 3 = event-type-specific
    // u64 payload (faulting address for memory_fault, etc.). Both ride
    // alongside the syscall-word return.
    const target_ctx = receiver.iret_frame orelse receiver.ctx;
    arch.syscall.setSyscallReturn(target_ctx, ret_word);
    arch.syscall.setEventSubcode(target_ctx, subcode);
    arch.syscall.setEventAddr(target_ctx, event_addr);

    _ = p;
    return 0;
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
