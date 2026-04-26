//! Timer — kernel object that fires once or periodically and exposes
//! a u64 counter directly in its handle's field0. Userspace observes
//! fires by polling the counter or waiting on it via `futex_wait_val`
//! (the handle table is mapped read-only into the holding domain so
//! the counter's vaddr is a valid futex address). See spec §[timer].
//!
//! Refcount lifetime — total handles keep the timer alive. When the
//! last handle drops the kernel cancels (if armed) and reclaims state.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const capability = zag.caps.capability;
const futex = zag.sched.futex;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const CapabilityType = zag.caps.capability.CapabilityType;
const ErasedSlabRef = zag.caps.capability.ErasedSlabRef;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SpinLock = zag.utils.sync.SpinLock;

/// Cap bits in `Capability.word0[48..63]` for timer handles.
/// Spec §[timer] cap layout.
pub const TimerCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    arm: bool = false,
    cancel: bool = false,
    restart_policy: u1 = 0,
    _reserved: u11 = 0,
};

/// Cancellation sentinel for `Timer.counter`. Reserved value distinct
/// from any real fire-driven value because increments saturate at
/// `u64::MAX − 1`.
pub const CANCELLED: u64 = std.math.maxInt(u64);

/// Saturation ceiling for fire-driven counter increments. One below
/// `CANCELLED` so a real counter value never collides with the
/// cancellation sentinel.
pub const COUNTER_CEILING: u64 = std.math.maxInt(u64) - 1;

/// Spec error codes used by this module.
const E_PERM: i64 = -12;
const E_BADCAP: i64 = -3;
const E_INVAL: i64 = -7;
const E_NOMEM: i64 = -10;
const E_FULL: i64 = -6;

/// Reserved-bit masks for the public ABI.
const TIMER_CAPS_RESERVED_MASK: u64 = 0xFFFF_FFFF_FFFF_0000;
const TIMER_FLAGS_RESERVED_MASK: u64 = ~@as(u64, 1);

pub const Timer = struct {
    /// Slab generation lock + per-instance mutex.
    _gen_lock: GenLock = .{},

    /// Total user-visible handles across all capability domains.
    /// Mutated under `_gen_lock`; the decrementer that brings this to
    /// 0 cancels (if armed) and frees.
    refcount: u32 = 0,

    /// Fire counter. Incremented on each fire, saturating at
    /// `u64::MAX − 1`. Set to `CANCELLED` (u64::MAX) by `timer_cancel`.
    /// Reset to 0 by `timer_rearm`. Mirrors user-visible field0 and
    /// is eagerly propagated to every domain-local copy of the handle
    /// (not atomically across copies — transient divergence between
    /// copies is permitted).
    counter: u64 = 0,

    /// Armed flag. True between arm/rearm and either cancel or one-
    /// shot fire. Mirrors field1 bit 0.
    armed: bool = false,

    /// Periodic flag. True for periodic timers that re-arm after each
    /// fire; false for one-shots. Mirrors field1 bit 1.
    periodic: bool = false,

    /// Period in nanoseconds for periodic timers; one-shot interval
    /// for non-periodic. Set by arm/rearm.
    period_ns: u64 = 0,

    /// Next absolute fire time in monotonic clock nanoseconds. Used
    /// by the timer wheel to fire when the deadline passes.
    deadline_ns: u64 = 0,
};

pub const Allocator = SecureSlab(Timer, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

/// Global next-soonest deadline guard. The per-core hardware deadline
/// is only re-armed when a fresh `wheelInsert` lands earlier than every
/// other live timer. `0` = no live deadlines.
var earliest_deadline_ns: u64 = 0;
var wheel_lock: SpinLock = .{ .class = "sched.timer.wheel_lock" };

// ── External API ─────────────────────────────────────────────────────

/// `timer_arm` syscall handler. Spec §[timer].
pub fn timerArm(caller: *anyopaque, caps: u64, deadline_ns: u64, flags: u64) i64 {
    if (deadline_ns == 0) return E_INVAL;
    if ((caps & TIMER_CAPS_RESERVED_MASK) != 0) return E_INVAL;
    if ((flags & TIMER_FLAGS_RESERVED_MASK) != 0) return E_INVAL;

    const caller_domain = callerDomain(caller) orelse return E_PERM;
    if (!callerHasTimerCap(caller_domain)) return E_PERM;

    const requested_caps: u16 = @truncate(caps);
    const periodic_flag: bool = (flags & 1) != 0;
    if (!checkRestartPolicyCeiling(caller_domain, requested_caps)) return E_PERM;

    const t = allocTimer(periodic_flag, deadline_ns) catch return E_NOMEM;
    const ref = ErasedSlabRef{
        .ptr = @ptrCast(t),
        .gen = @intCast(t._gen_lock.currentGen()),
    };

    const slot = zag.capdom.capability_domain.mintHandle(
        caller_domain,
        ref,
        .timer,
        requested_caps,
        0,
        encodeField1(true, periodic_flag),
    ) catch {
        destroyTimer(t);
        return E_FULL;
    };

    wheelInsert(t, t.deadline_ns);
    return @as(i64, slot);
}

/// `timer_rearm` syscall handler. Spec §[timer].
pub fn timerRearm(caller: *anyopaque, handle: u64, deadline_ns: u64, flags: u64) i64 {
    if ((flags & TIMER_FLAGS_RESERVED_MASK) != 0) return E_INVAL;

    const caller_domain = callerDomain(caller) orelse return E_PERM;
    const lookup = resolveTimerHandle(caller_domain, handle, .timer) orelse return E_BADCAP;
    refreshHandleSnapshot(caller_domain, lookup.slot, lookup.timer);

    if (deadline_ns == 0) return E_INVAL;
    if (!handleHasArmCap(caller_domain, lookup.slot)) return E_PERM;

    const periodic_flag: bool = (flags & 1) != 0;

    lookup.timer._gen_lock.lock(@src());
    if (lookup.timer.armed) wheelRemove(lookup.timer);
    lookup.timer.counter = 0;
    lookup.timer.armed = true;
    lookup.timer.periodic = periodic_flag;
    lookup.timer.period_ns = deadline_ns;
    lookup.timer.deadline_ns = currentNs() +| deadline_ns;
    lookup.timer._gen_lock.unlock();

    propagateAndWake(lookup.timer, 0);
    propagateField1(lookup.timer, encodeField1(true, periodic_flag));
    wheelInsert(lookup.timer, lookup.timer.deadline_ns);
    return 0;
}

/// `timer_cancel` syscall handler. Spec §[timer].
pub fn timerCancel(caller: *anyopaque, handle: u64) i64 {
    const caller_domain = callerDomain(caller) orelse return E_PERM;
    const lookup = resolveTimerHandle(caller_domain, handle, .timer) orelse return E_BADCAP;
    refreshHandleSnapshot(caller_domain, lookup.slot, lookup.timer);

    if (!handleHasCancelCap(caller_domain, lookup.slot)) return E_PERM;

    lookup.timer._gen_lock.lock(@src());
    if (!lookup.timer.armed) {
        lookup.timer._gen_lock.unlock();
        return E_INVAL;
    }
    wheelRemove(lookup.timer);
    lookup.timer.armed = false;
    lookup.timer.counter = CANCELLED;
    lookup.timer._gen_lock.unlock();

    propagateAndWake(lookup.timer, CANCELLED);
    propagateField1(lookup.timer, encodeField1(false, lookup.timer.periodic));
    return 0;
}

// ── Internal API ─────────────────────────────────────────────────────

/// Allocate a Timer (refcount=1, counter=0, armed=true). Spec §[timer].
fn allocTimer(periodic: bool, deadline_ns: u64) !*Timer {
    const ref = try slab_instance.create();
    const t = ref.ptr;
    t.refcount = 1;
    t.counter = 0;
    t.armed = true;
    t.periodic = periodic;
    t.period_ns = deadline_ns;
    t.deadline_ns = currentNs() +| deadline_ns;
    return t;
}

/// Final teardown — cancels (if armed), removes from wheel, frees slab.
fn destroyTimer(t: *Timer) void {
    const gen = t._gen_lock.currentGen();
    if (t.armed) {
        wheelRemove(t);
        t.armed = false;
    }
    slab_instance.destroy(t, gen) catch {};
}

/// Handle copy: increment refcount under `_gen_lock`.
pub fn incHandleRef(t: *Timer) void {
    t._gen_lock.lock(@src());
    defer t._gen_lock.unlock();
    t.refcount +|= 1;
}

/// Handle delete: decrement under `_gen_lock`; teardown at 0.
pub fn decHandleRef(t: *Timer) void {
    t._gen_lock.lock(@src());
    if (t.refcount > 0) t.refcount -= 1;
    const last = t.refcount == 0;
    t._gen_lock.unlock();
    if (last) destroyTimer(t);
}

/// Insert into the timer wheel at `deadline_ns`. If this is now the
/// next-soonest deadline globally, re-arm the per-core hardware deadline
/// so the wheel ISR fires when it expires.
fn wheelInsert(t: *Timer, deadline_ns: u64) void {
    const irq = wheel_lock.lockIrqSave(@src());
    defer wheel_lock.unlockIrqRestore(irq);

    wheelInsertLocked(t, deadline_ns);

    if (earliest_deadline_ns == 0 or deadline_ns < earliest_deadline_ns) {
        earliest_deadline_ns = deadline_ns;
        arch.time.armWheelDeadline(deadline_ns);
    }
}

/// Wheel-storage insertion. Topology (hierarchical wheel buckets vs.
/// flat ordered list) is owned by the wheel implementation; this
/// placeholder reserves the call site so timerArm/timerRearm/onFire
/// don't need to grow when the storage backend lands.
fn wheelInsertLocked(t: *Timer, deadline_ns: u64) void {
    _ = t;
    _ = deadline_ns;
}

/// Remove from the timer wheel (idempotent).
fn wheelRemove(t: *Timer) void {
    const irq = wheel_lock.lockIrqSave(@src());
    defer wheel_lock.unlockIrqRestore(irq);
    wheelRemoveLocked(t);
}

fn wheelRemoveLocked(t: *Timer) void {
    _ = t;
}

/// Fire callback — invoked from the wheel when `deadline_ns` expires.
/// Increments counter (saturating at `COUNTER_CEILING`), propagates to
/// every domain-local copy of the handle, futex-wakes each copy's
/// `field0` paddr. Re-arms if periodic.
pub fn onFire(t: *Timer) void {
    t._gen_lock.lock(@src());
    if (!t.armed) {
        t._gen_lock.unlock();
        return;
    }
    const new_count = if (t.counter >= COUNTER_CEILING)
        COUNTER_CEILING
    else
        t.counter + 1;
    t.counter = new_count;

    const periodic = t.periodic;
    var next_deadline: u64 = 0;
    if (periodic) {
        next_deadline = t.deadline_ns +| t.period_ns;
        t.deadline_ns = next_deadline;
    } else {
        t.armed = false;
    }
    t._gen_lock.unlock();

    propagateAndWake(t, new_count);
    if (!periodic) {
        propagateField1(t, encodeField1(false, false));
    } else {
        wheelInsert(t, next_deadline);
    }
}

/// Walk every domain-local copy of this Timer's handle, writing
/// `value` into each `Capability.field0`, futex-waking the paddr, and
/// kicking idle remote cores so they re-evaluate the wake. Spec §[timer]
/// (eager but non-atomic propagation across copies).
fn propagateAndWake(t: *Timer, value: u64) void {
    var iter = handleHolderIterator(t);
    while (iter.next()) |loc| {
        const field0_paddr = computeFieldPaddr(loc.domain, loc.slot, .field0);
        arch.userio.writeU64ViaPhysmap(field0_paddr, value);
        _ = futex.wake(field0_paddr, std.math.maxInt(u32));
        if (loc.core_id) |core| arch.smp.sendWakeIpi(core);
    }
}

/// Mirror updated `field1` (arm/pd bits) into every domain-local copy.
/// No futex wake — userspace observes arm/pd transitions through
/// `sync` or as a side effect of the field0 wake.
fn propagateField1(t: *Timer, value: u64) void {
    var iter = handleHolderIterator(t);
    while (iter.next()) |loc| {
        const field1_paddr = computeFieldPaddr(loc.domain, loc.slot, .field1);
        arch.userio.writeU64ViaPhysmap(field1_paddr, value);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

const TimerLookup = struct {
    timer: *Timer,
    slot: u12,
};

const HandleField = enum { field0, field1 };

const HandleLocation = struct {
    domain: *CapabilityDomain,
    slot: u12,
    /// Core a wake IPI should target if any EC bound to this domain is
    /// currently idle. `null` = no wake hint available.
    core_id: ?u64,
};

/// Enumerator over every `(CapabilityDomain, slot)` pair holding a
/// handle to `t`. The cross-domain handle index needed to back this
/// lives in the capability layer; this iterator is the call-site shape
/// timer fire/cancel/rearm propagation needs once that index lands.
const HandleHolderIterator = struct {
    timer: *Timer,

    fn next(self: *HandleHolderIterator) ?HandleLocation {
        _ = self;
        return null;
    }
};

fn handleHolderIterator(t: *Timer) HandleHolderIterator {
    return .{ .timer = t };
}

fn callerDomain(caller: *anyopaque) ?*CapabilityDomain {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const dom = ec.domain.lock(@src()) catch return null;
    ec.domain.unlock();
    return dom;
}

fn callerHasTimerCap(cd: *CapabilityDomain) bool {
    _ = cd;
    return true;
}

fn checkRestartPolicyCeiling(cd: *CapabilityDomain, requested: u16) bool {
    _ = cd;
    _ = requested;
    return true;
}

fn resolveTimerHandle(cd: *CapabilityDomain, handle: u64, expected: CapabilityType) ?TimerLookup {
    const slot_id = capability.Word0.id(handle);
    const t_tag = capability.Word0.typeTag(handle);
    if (t_tag != expected) return null;

    const kernel_entry = &cd.kernel_table[slot_id];
    const typed = capability.typedRef(Timer, kernel_entry.*) orelse return null;
    const ptr = typed.lock(@src()) catch return null;
    typed.unlock();
    return .{ .timer = ptr, .slot = slot_id };
}

fn handleHasArmCap(cd: *CapabilityDomain, slot: u12) bool {
    const caps = capability.Word0.caps(cd.user_table[slot].word0);
    const tc: TimerCaps = @bitCast(caps);
    return tc.arm;
}

fn handleHasCancelCap(cd: *CapabilityDomain, slot: u12) bool {
    const caps = capability.Word0.caps(cd.user_table[slot].word0);
    const tc: TimerCaps = @bitCast(caps);
    return tc.cancel;
}

fn refreshHandleSnapshot(cd: *CapabilityDomain, slot: u12, t: *Timer) void {
    t._gen_lock.lock(@src());
    const counter = t.counter;
    const armed = t.armed;
    const periodic = t.periodic;
    t._gen_lock.unlock();
    cd.user_table[slot].field0 = counter;
    cd.user_table[slot].field1 = encodeField1(armed, periodic);
}

fn encodeField1(armed: bool, periodic: bool) u64 {
    return (@as(u64, @intFromBool(armed))) |
        (@as(u64, @intFromBool(periodic)) << 1);
}

/// Resolve the physical address backing `field0`/`field1` of the handle
/// in slot `slot` of `cd`'s user table. Per-handle propagation needs
/// the paddr (not vaddr) because the kernel writes into every copy of
/// the read-only user-mapped table via the kernel physmap.
fn computeFieldPaddr(cd: *CapabilityDomain, slot: u12, which: HandleField) PAddr {
    const entry: *capability.Capability = &cd.user_table[slot];
    const field_addr: usize = switch (which) {
        .field0 => @intFromPtr(&entry.field0),
        .field1 => @intFromPtr(&entry.field1),
    };
    return PAddr.fromVAddr(.{ .addr = field_addr }, null);
}

fn currentNs() u64 {
    return arch.time.currentMonotonicNs();
}
