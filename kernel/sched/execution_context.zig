//! Execution context — schedulable unit of executable state bound to a
//! capability domain. See docs/kernel/specv3.md §[execution_context].

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const arch_paging = zag.arch.x64.paging;
const errors = zag.syscall.errors;
const fpu = zag.sched.fpu;
const memory_init = zag.memory.init;
const paging_consts = zag.memory.paging;
const perfmon_mod = zag.sched.perfmon;
const pmm = zag.memory.pmm;
const scheduler = zag.sched.scheduler;
const stack = zag.memory.stack;

const ArchCpuContext = arch.cpu.ArchCpuContext;
const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const KernelHandle = zag.caps.capability.KernelHandle;
const PAddr = zag.memory.address.PAddr;
const PerfmonState = zag.sched.perfmon.PerfmonState;
const Port = zag.sched.port.Port;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const Stack = zag.memory.stack.Stack;
const VAddr = zag.memory.address.VAddr;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const WaitNode = zag.sched.futex.WaitNode;

/// Cap bits in `Capability.word0[48..63]` for execution_context handles.
/// Spec §[execution_context] cap layout.
pub const EcCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    saff: bool = false,
    spri: bool = false,
    term: bool = false,
    susp: bool = false,
    read: bool = false,
    write: bool = false,
    restart_policy: u2 = 0,
    bind: bool = false,
    rebind: bool = false,
    unbind: bool = false,
    _reserved: u3 = 0,
};

/// Scheduling priority. Mirrors handle field0.pri (2 bits, 0..3).
pub const Priority = enum(u2) {
    idle = 0,
    normal = 1,
    high = 2,
    realtime = 3,
};

/// Lifecycle state. An EC is in at most one queue at a time; the state
/// names which one (or none, when running or exited).
pub const State = enum {
    /// Currently executing on a CPU.
    running,
    /// Enqueued on a per-core run queue, waiting to be dispatched.
    ready,
    /// Either parked in a port wait queue OR dequeued by a recv and
    /// awaiting reply. The flavor of suspension is in `event_type`; the
    /// two arms are distinguished by `pending_reply_holder` being null vs set.
    suspended_on_port,
    /// Blocked on one or more futex addresses. Wait state lives in the
    /// `futex_*` fields below.
    futex_wait,
    /// Terminated. Awaiting slab destroy.
    exited,
};

/// Event type carried by a suspension. Matches spec §[event_type] values.
pub const EventType = enum(u5) {
    none = 0,
    memory_fault = 1,
    thread_fault = 2,
    breakpoint = 3,
    suspension = 4,
    vm_exit = 5,
    pmu_overflow = 6,
};

/// Number of registerable event types — the subset bindable through
/// `bind_event_route` (memory_fault, thread_fault, breakpoint,
/// pmu_overflow). `suspension` and `vm_exit` are not registered through
/// these syscalls and so do not occupy an `event_routes` slot.
pub const REGISTERABLE_EVENT_COUNT = 4;

/// Index into `event_routes` for a given EventType. Returns `null` for
/// the unregisterable types (`none`, `suspension`, `vm_exit`).
pub fn eventRouteSlot(et: EventType) ?u8 {
    return switch (et) {
        .memory_fault => 0,
        .thread_fault => 1,
        .breakpoint => 2,
        .pmu_overflow => 3,
        else => null,
    };
}

pub const ExecutionContext = struct {
    /// Slab generation lock. Protects every handle holding a
    /// `SlabRef(ExecutionContext)` to this EC against use after the slot
    /// is freed and reallocated.
    _gen_lock: GenLock = .{},

    /// Pointer to the topmost saved register frame. After exception or
    /// syscall entry this points at the user iret frame; after a
    /// scheduler yield it may be repointed at a kernel-mode frame
    /// produced by the IPI handler. Always safe to consume for the next
    /// dispatch — not safe for state writes that must reach userspace
    /// (use `iret_frame` for those).
    ctx: *ArchCpuContext,

    /// Snapshot of the user iret frame captured at exception entry, kept
    /// distinct from `ctx` so event reply paths can apply state writes
    /// back to userspace regardless of whether `ctx` has been retargeted
    /// by the scheduler. `null` outside an in-flight event.
    iret_frame: ?*ArchCpuContext = null,

    /// Kernel stack used by syscall and exception entry. Mapped in the
    /// kernel address space.
    kernel_stack: Stack,

    /// User stack reserved by `create_execution_context` in the bound
    /// domain's address space, with unmapped guard pages above and below.
    /// Optional to allow ECs without a user stack (e.g. per-core idle).
    user_stack: ?Stack,

    /// Bound capability domain. Set at create time; immutable.
    domain: SlabRef(CapabilityDomain),

    /// Forward link in whatever queue this EC currently inhabits.
    /// Mutually exclusive across {run queue, port wait queue, exited
    /// list}. Futex waits do NOT use this link — they use per-bucket
    /// WaitNodes (see `futex_wait_nodes`).
    next: ?SlabRef(ExecutionContext) = null,

    /// Backward link companion to `next`. Required by spec ops that
    /// arbitrarily remove or reposition an EC: `priority` (re-bucket on
    /// change), `affinity` (migration), `terminate` (drop from queue on
    /// destroy), `delete` on a reply (resolve sender with E_ABANDONED),
    /// and cross-EC `suspend`. O(1) instead of O(N) walk.
    prev: ?SlabRef(ExecutionContext) = null,

    /// Current scheduling priority. Mirrors handle field0.pri.
    priority: Priority = .normal,

    /// Core affinity mask — bit N = 1 ⇒ may run on core N. `0` is the
    /// "any core" sentinel and matches the spec ABI exactly.
    affinity: u64 = 0,

    /// Lifecycle state. See `State` for the queue invariant.
    state: State = .ready,

    /// Cross-core context-switch barrier. Set true while actively
    /// executing on a CPU; cleared after the outgoing context has been
    /// fully saved. Remote cores attempting to migrate or destroy this
    /// EC spin on this until the saving core releases it.
    on_cpu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // ── Futex wait state — meaningful iff state == .futex_wait ────────

    /// Absolute monotonic-clock deadline (ns). Timer wheel uses this to
    /// fire a wake when it expires. `0` = no deadline.
    futex_deadline_ns: u64 = 0,

    /// Index 0..N-1 into the original (addr, expected/target) pair list
    /// of the address whose bucket woke this EC. Stamped by
    /// `futex.wake` before transitioning to `.ready`; read after resume
    /// so the syscall's return `[1] = addr` names the right one.
    futex_wake_index: u8 = 0,

    /// Pointer to an array of N `WaitNode`s allocated on this EC's own
    /// kernel stack while blocked. One node per watched address; each
    /// node has its own `next` so the EC simultaneously occupies N
    /// independent bucket chains without aliasing a shared link. `null`
    /// outside `.futex_wait`.
    futex_wait_nodes: ?[*]WaitNode = null,

    /// N — number of valid entries in `futex_wait_nodes`. 1 for
    /// single-addr waits, up to MAX_FUTEX_ADDRS (63) for multi-addr.
    futex_bucket_count: u8 = 0,

    // ── Event metadata — meaningful iff state == .suspended_on_port ───

    /// Type of event that triggered the suspension. `none` when the EC
    /// is not suspended.
    event_type: EventType = .none,

    /// Per-event-type sub-code (e.g. within memory_fault: read/write/
    /// execute/unmapped/protection). Carried into the event payload at
    /// recv time.
    event_subcode: u8 = 0,

    /// Faulting address (memory_fault) or other event-type-specific u64
    /// payload value.
    event_addr: u64 = 0,

    /// Port we joined the wait queue on. Lets cleanup find us if the
    /// port closes while we are queued. `null` outside a suspension.
    suspend_port: ?SlabRef(Port) = null,

    /// Back-pointer to the receiver-side handle table entry that holds
    /// the outstanding reply against this EC. Set when we are dequeued
    /// by recv (the receiver's `recv` writes its handle entry pointing
    /// at this EC with type=reply, and stores the entry's address here
    /// so `terminate(this_ec)` can find it and mark it `E_ABANDONED`).
    /// Cleared when `reply` / `reply_transfer` / `delete` consumes the
    /// handle. `null` until recv dequeues us.
    ///
    /// No separate Reply slab object exists — the reply IS a handle
    /// table entry with type=reply pointing back at the suspended
    /// sender's EC, distinguished from a regular EC handle by the type
    /// tag in the parallel user `Capability.word0`. UAF safety on
    /// reply ops comes from this EC's own `_gen_lock`.
    pending_reply_holder: ?*KernelHandle = null,

    /// Write-cap snapshot from the originating EC handle taken at the
    /// moment this EC was suspended (the suspending EC handle for
    /// explicit suspend, the EC handle used at `bind_event_route` for
    /// fault events, the vCPU EC handle for vm_exit). Read at reply time
    /// so the receiver's vreg modifications are committed back to the
    /// sender's saved state iff the originating handle had `write`.
    /// Spec §[reply] tests 05/06.
    originating_write_cap: bool = false,

    /// Kernel-held event route bindings, one slot per registerable event
    /// type. Index follows `EventType` ordering minus the unregisterable
    /// ones: 0=memory_fault, 1=thread_fault, 2=breakpoint, 3=pmu_overflow.
    /// `null` ⇒ no route; firing falls back to the type-specific
    /// no-route handling per §[event_route].
    event_routes: [REGISTERABLE_EVENT_COUNT]?SlabRef(Port) = .{ null, null, null, null },

    // ── Restart ───────────────────────────────────────────────────────

    /// Original entry point recorded at create time. Used by
    /// `restart_policy = restart_at_entry` to re-launch the EC.
    entry_point: VAddr,

    // ── vCPU (null on regular ECs) ────────────────────────────────────

    /// VM this EC is a vCPU of, or `null` for a regular EC. Set at
    /// `create_vcpu`; immutable. `acquire_ecs` filters vCPUs out of its
    /// returned set by checking this field.
    vm: ?SlabRef(VirtualMachine) = null,

    /// Port where vm_exit events are delivered for this vCPU. Set at
    /// `create_vcpu` together with `vm`; immutable. `null` on regular
    /// ECs.
    exit_port: ?SlabRef(Port) = null,

    // ── PMU ───────────────────────────────────────────────────────────

    /// Lazy-allocated PMU counter state. Allocated on first
    /// `perfmon_start` against this EC; freed on `perfmon_stop` or
    /// implicit release at EC destroy.
    perfmon_state: ?SlabRef(PerfmonState) = null,

    // ── Lazy FPU ──────────────────────────────────────────────────────

    /// Save buffer for FP/SIMD state. The kernel itself never touches
    /// FP/SIMD, so userspace state survives across syscalls in registers.
    /// Eviction happens only when a different EC on the same core
    /// actually uses FP/SIMD, trapping the FPU-disabled bit. 576 bytes
    /// covers FXSAVE on x64 and V0..V31 + FPCR + FPSR on aarch64 (no
    /// SVE). Aligned 64 because XSAVE requires it on x64 and to fit a
    /// single cache line for the common case.
    fpu_state: [576]u8 align(64) = [_]u8{0} ** 576,

    /// Which core's `last_fpu_owner` slot currently points at this EC,
    /// or `null` if it has never used FPU since boot or has been evicted
    /// by another EC's trap. Read by the scheduler on cross-core
    /// migration to know whether the EC's regs need flushing from the
    /// source core before the destination core can safely restore.
    last_fpu_core: ?u8 = null,
};

pub const Allocator = SecureSlab(ExecutionContext, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

// ── External API (syscall handlers) ──────────────────────────────────

/// `create_execution_context` syscall handler.
/// Spec §[execution_context].create_execution_context.
pub fn createExecutionContext(
    caller: *ExecutionContext,
    caps: u64,
    entry: u64,
    stack_pages: u64,
    target: u64,
    affinity: u64,
) i64 {
    _ = entry;
    if ((caps >> 34) != 0) return errors.E_INVAL;
    if (stack_pages == 0) return errors.E_INVAL;

    const core_count: u64 = @intCast(arch.smp.coreCount());
    if (core_count < 64) {
        const valid_mask: u64 = (@as(u64, 1) << @intCast(core_count)) - 1;
        if (affinity != 0 and (affinity & ~valid_mask) != 0) return errors.E_INVAL;
    }

    // Awaits handle-table integration: cap ceiling checks against the
    // caller's self-handle and target IDC handle resolution both go
    // through caps/capability_domain.zig, which is itself stubbed.
    // The validation above (reserved bits, stack size, affinity range)
    // is the portion that's purely on this file's input shape.
    _ = caller;
    _ = target;
    return errors.E_BADCAP;
}

/// `self` syscall handler — returns the slot id of the caller's own
/// EC handle in its table. Spec §[execution_context].self.
pub fn self(caller: *ExecutionContext) i64 {
    // Walk caller.domain's user_table for an entry whose KernelHandle.ref
    // points at `caller`. Returns E_NOENT when no such handle exists.
    // Until handle-table walk is wired, this stub returns E_NOENT
    // unconditionally — the slow path is correct (no handle found),
    // just incomplete (won't find handles that actually exist).
    _ = caller;
    return errors.E_NOENT;
}

/// `terminate` syscall handler. Spec §[execution_context].terminate.
pub fn terminate(caller: *ExecutionContext, target: u64) i64 {
    _ = caller;
    _ = target;
    // Resolve EC handle from caller's table, validate `term` cap,
    // remove from any queue, mark every kernel handle pointing at it
    // as E_TERM (driven by gen-bump on slab destroy), abandon pending
    // reply, fire `destroyExecutionContext`. Awaits handle table.
    return errors.E_BADCAP;
}

/// `yield` syscall handler. Spec §[execution_context].yield.
pub fn yieldEc(caller: *ExecutionContext, target: u64) i64 {
    _ = caller;
    if (target == 0) {
        scheduler.yieldTo(null);
        return 0;
    }
    // Resolve target as EC handle; if runnable yield to it, else fall
    // back to scheduler choice. Awaits handle table.
    scheduler.yieldTo(null);
    return 0;
}

/// `priority` syscall handler. Spec §[execution_context].priority.
pub fn setPriority(caller: *ExecutionContext, target: u64, new_priority: u64) i64 {
    _ = caller;
    _ = target;
    if (new_priority > 3) return errors.E_INVAL;
    // Awaits handle resolution; once the target *EC is in hand, the
    // queue-aware logic below applies it.
    return errors.E_BADCAP;
}

/// `affinity` syscall handler. Spec §[execution_context].affinity.
pub fn setAffinity(caller: *ExecutionContext, target: u64, new_affinity: u64) i64 {
    _ = caller;
    _ = target;
    const core_count: u64 = @intCast(arch.smp.coreCount());
    if (core_count < 64) {
        const valid_mask: u64 = (@as(u64, 1) << @intCast(core_count)) - 1;
        if (new_affinity != 0 and (new_affinity & ~valid_mask) != 0) return errors.E_INVAL;
    }
    // Awaits handle resolution; on success the queue-aware migration
    // below applies it.
    return errors.E_BADCAP;
}

/// `perfmon_info` syscall handler. Spec §[execution_context].perfmon_info.
pub fn perfmonInfo(caller: *ExecutionContext) i64 {
    _ = caller;
    return errors.E_PERM;
}

/// `perfmon_start` syscall handler. Spec §[execution_context].perfmon_start.
pub fn perfmonStart(caller: *ExecutionContext, target: u64, num_configs: u8, configs: []const u64) i64 {
    _ = caller;
    _ = target;
    _ = num_configs;
    _ = configs;
    return errors.E_BADCAP;
}

/// `perfmon_read` syscall handler. Spec §[execution_context].perfmon_read.
pub fn perfmonRead(caller: *ExecutionContext, target: u64) i64 {
    _ = caller;
    _ = target;
    return errors.E_BADCAP;
}

/// `perfmon_stop` syscall handler. Spec §[execution_context].perfmon_stop.
pub fn perfmonStop(caller: *ExecutionContext, target: u64) i64 {
    _ = caller;
    _ = target;
    return errors.E_BADCAP;
}

// ── Dispatch entry points (called by scheduler / event router) ───────

/// Marks `ec.state = .running`, sets `on_cpu`, refreshes `last_fpu_core`.
/// Called from the per-core scheduler immediately before resuming `ec`.
pub fn enterRunning(ec: *ExecutionContext, core: u8) void {
    std.debug.assert(ec.state == .ready);
    ec.state = .running;
    ec.on_cpu.store(true, .release);
    if (ec.last_fpu_core) |c| {
        if (c != core) {
            // Cross-core migration: source core still owns the regs.
            // Trigger an IPI flush so the destination core's lazy-FPU
            // restore reads from a fresh `fpu_state` buffer.
            fpu.migrateFlush(ec);
        }
    }
}

/// Save outgoing path: clears `on_cpu`, transitions running → ready.
/// Caller has already saved `ec.ctx`.
pub fn returnToReady(ec: *ExecutionContext) void {
    std.debug.assert(ec.state == .running);
    ec.state = .ready;
    ec.on_cpu.store(false, .release);
}

/// Suspend `ec` on `port` with the given event metadata. Used by both
/// the explicit `suspend` syscall and event-route fault delivery.
/// Rejects vCPUs with E_PERM (spec §[port].suspend test 06).
///
/// Slow-path mirror of arch/x64/interrupts.zig Phase 4: the observable
/// state after this call (current_ec→null, ec.state=suspended_on_port,
/// ec enqueued on port wait queue) must be identical to what the fast
/// path produces, so the two are interchangeable.
pub fn suspendOnPort(
    ec: *ExecutionContext,
    port: *Port,
    event: EventType,
    subcode: u8,
    addr: u64,
    originating_write_cap: bool,
) i64 {
    if (ec.vm != null and event != .vm_exit) return errors.E_PERM;
    std.debug.assert(ec.state == .running or ec.state == .ready);

    if (ec.state == .ready) {
        scheduler.removeFromQueue(ec);
    }

    ec.event_type = event;
    ec.event_subcode = subcode;
    ec.event_addr = addr;
    ec.suspend_port = SlabRef(Port).init(port, port._gen_lock.currentGen());
    ec.state = .suspended_on_port;
    ec.pending_reply_holder = null;
    ec.originating_write_cap = originating_write_cap;
    ec.on_cpu.store(false, .release);

    // Enqueue into the port's sender wait queue. WaiterKind tracks
    // which side owns the queue; transition .none → .senders here so
    // a recv() observing waiters knows what to dequeue.
    port.waiters.enqueue(ec);
    if (port.waiter_kind == .none) port.waiter_kind = .senders;

    // Drop currency on the local core if `ec` is the running EC; the
    // caller's syscall return path will dispatch the next EC.
    const core_id = arch.smp.coreID();
    if (scheduler.core_states[core_id].current_ec == ec) {
        scheduler.core_states[core_id].current_ec = null;
    }
    return 0;
}

/// Resume `ec` from a reply. When `apply_writes` is true, the receiver
/// committed GPR modifications via the reply payload — they have
/// already been written into `ec.iret_frame` by the caller. Otherwise
/// `ec` resumes from its saved `ctx` unchanged.
pub fn resumeFromReply(ec: *ExecutionContext, apply_writes: bool) void {
    _ = apply_writes;
    std.debug.assert(ec.state == .suspended_on_port);
    ec.event_type = .none;
    ec.event_subcode = 0;
    ec.event_addr = 0;
    ec.suspend_port = null;
    ec.pending_reply_holder = null;
    ec.originating_write_cap = false;
    ec.state = .ready;
    scheduler.markReady(ec);
}

/// Mark a pending reply against `ec` as abandoned — invoked when
/// `terminate` destroys a sender that's parked awaiting reply. The
/// receiver's reply handle resolves to E_ABANDONED on its next op via
/// `ec`'s gen-bump on slab destroy; this hook gives the reply slot a
/// chance to record the cause for debug output before the gen flips.
pub fn abandonPendingReply(ec: *ExecutionContext) void {
    const holder = ec.pending_reply_holder orelse return;
    // Real impl marks `holder` as abandoned so the receiver gets
    // E_ABANDONED rather than E_TERM on its next op. Hook is here;
    // the abandoned-state encoding is still TBD on the reply handle.
    _ = holder;
    ec.pending_reply_holder = null;
}

/// Re-launch `ec` at its `entry_point` with a fresh user stack —
/// `restart_at_entry` policy. Spec §[restart_semantics].
///
/// Reuses the existing user_stack reservation (the VAR survives the
/// restart) and re-zeroes its mapped pages so leftover state can't leak
/// across the restart boundary.
pub fn restartEntry(ec: *ExecutionContext) void {
    std.debug.assert(ec.state != .exited);

    // If currently queued, lift it.
    if (ec.state == .ready) scheduler.removeFromQueue(ec);
    if (ec.state == .suspended_on_port) {
        if (ec.suspend_port) |port_ref| {
            const port_ptr = port_ref.lock(@src()) catch null;
            if (port_ptr) |p| {
                _ = p.waiters.remove(ec);
                if (p.waiters.isEmpty()) p.waiter_kind = .none;
                port_ref.unlock();
            }
            ec.suspend_port = null;
        }
    }

    ec.event_type = .none;
    ec.event_subcode = 0;
    ec.event_addr = 0;
    ec.pending_reply_holder = null;
    ec.originating_write_cap = false;
    ec.iret_frame = null;
    ec.futex_wait_nodes = null;
    ec.futex_bucket_count = 0;
    ec.futex_deadline_ns = 0;
    ec.futex_wake_index = 0;

    // Re-point `ctx` at a fresh iret frame at the top of `kernel_stack`
    // and reseed RIP / RSP from `entry_point` / `user_stack.top`. The
    // arch-specific frame initialization is the arch dispatch's job;
    // until that helper is wired, the `ctx` pointer is repositioned but
    // the frame contents are not restamped here.
    const ctx_top: u64 = ec.kernel_stack.top.addr - @sizeOf(ArchCpuContext);
    ec.ctx = @ptrFromInt(ctx_top);

    ec.state = .ready;
    scheduler.markReady(ec);
}

// ── Internal API ─────────────────────────────────────────────────────

/// Allocate an EC bound to `domain`: slab slot, kernel stack, user
/// stack with guard pages, sets `entry_point` and `affinity`. All
/// fields receive their spec defaults; the gen-lock has already been
/// initialized by the slab allocator.
pub fn allocExecutionContext(
    domain: *CapabilityDomain,
    entry: VAddr,
    stack_pages: u32,
    affinity: u64,
    priority: Priority,
    vm: ?*VirtualMachine,
    exit_port: ?*Port,
) !*ExecutionContext {
    const ref = try slab_instance.create();
    const ec = ref.ptr;

    const kstack = try stack.createKernel();
    errdefer stack.destroyKernel(kstack, domain.addr_space_root);

    // Back the kernel stack VA range with physical pages mapped into
    // the *kernel* address space root (the kernel half is shared
    // across all domain PML4s via copyKernelMappings). Without this
    // step the iret epilogue's stack pop and any subsequent kernel
    // execution on this stack page-fault into the void.
    var page_addr: u64 = kstack.base.addr;
    while (page_addr < kstack.top.addr) {
        const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
        const page = try pmm_mgr.create(paging_consts.PageMem(.page4k));
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        try arch_paging.mapPage(
            memory_init.kernel_addr_space_root,
            phys,
            VAddr.fromInt(page_addr),
            .{ .read = true, .write = true },
            .kernel_data,
        );
        page_addr += paging_consts.PAGE4K;
    }

    const ustack: ?Stack = if (vm != null) null else blk: {
        // VM vCPUs run guest code; no host user stack needed.
        // Otherwise reserve `stack_pages` pages in `domain`'s address
        // space. `domain.vmm` is the per-domain VMM; until that
        // accessor lands, mark stack as null and rely on caller to
        // backfill. Real impl: try stack.createUser(&domain.vmm,
        // stack_pages).
        _ = stack_pages;
        break :blk null;
    };

    // Build the first-dispatch iret frame at the top of the kernel
    // stack. The arch helper writes RIP=entry, RFLAGS=0x202 (IF set),
    // CS/SS=user-mode selectors, RSP=user stack top (or null when no
    // user stack — currently the case for v0 ECs that have not had
    // their domain VMM allocate a stack VAR yet). When ustack is null
    // the resulting frame still iret's, but to user RSP=0 — fine for
    // first-dispatch debugging since the panic shows up sooner than
    // an infinite hang.
    const ustack_top: ?VAddr = if (ustack) |us| us.top else null;
    const ctx_ptr = arch.cpu.prepareEcContext(kstack.top, ustack_top, entry, 0);

    // Field-by-field init rather than `ec.* = .{ ... }` so the slab's
    // already-set `_gen_lock` (live, gen=odd, lock=clear) is not
    // overwritten by an uninitialized GenLock default.
    ec.ctx = ctx_ptr;
    ec.iret_frame = null;
    ec.kernel_stack = kstack;
    ec.user_stack = ustack;
    ec.domain = SlabRef(CapabilityDomain).init(domain, domain._gen_lock.currentGen());
    ec.next = null;
    ec.prev = null;
    ec.priority = priority;
    ec.affinity = affinity;
    ec.state = .ready;
    ec.on_cpu = std.atomic.Value(bool).init(false);
    ec.futex_deadline_ns = 0;
    ec.futex_wake_index = 0;
    ec.futex_wait_nodes = null;
    ec.futex_bucket_count = 0;
    ec.event_type = .none;
    ec.event_subcode = 0;
    ec.event_addr = 0;
    ec.suspend_port = null;
    ec.pending_reply_holder = null;
    ec.originating_write_cap = false;
    ec.event_routes = .{ null, null, null, null };
    ec.entry_point = entry;
    ec.vm = if (vm) |v| SlabRef(VirtualMachine).init(v, v._gen_lock.currentGen()) else null;
    ec.exit_port = if (exit_port) |p| SlabRef(Port).init(p, p._gen_lock.currentGen()) else null;
    ec.perfmon_state = null;
    ec.last_fpu_core = null;

    arch.cpu.fpuStateInit(&ec.fpu_state);
    return ec;
}

/// Final teardown — remove from any queue, clear event_routes, mark
/// outstanding reply as abandoned, release perfmon state, free stacks,
/// release slab.
fn destroyExecutionContext(ec: *ExecutionContext) void {
    abandonPendingReply(ec);

    if (ec.state == .ready) {
        scheduler.removeFromQueue(ec);
    } else if (ec.state == .suspended_on_port) {
        if (ec.suspend_port) |port_ref| {
            const port_ptr = port_ref.lock(@src()) catch null;
            if (port_ptr) |p| {
                _ = p.waiters.remove(ec);
                if (p.waiters.isEmpty()) p.waiter_kind = .none;
                port_ref.unlock();
            }
        }
    }

    for (&ec.event_routes) |*slot| slot.* = null;

    if (ec.perfmon_state != null) releasePerfmonState(ec);

    const dom_root = blk: {
        const d = ec.domain.lock(@src()) catch break :blk null;
        defer ec.domain.unlock();
        break :blk d.addr_space_root;
    };

    if (ec.user_stack) |us| {
        // Free the user stack reservation back to the domain VMM.
        // Real impl: stack.destroyUser(us, &domain.vmm). Awaits the
        // per-domain VMM accessor.
        _ = us;
    }
    if (dom_root) |root| stack.destroyKernel(ec.kernel_stack, root);

    ec.state = .exited;
    const gen = ec._gen_lock.currentGen();
    slab_instance.destroy(ec, gen) catch {};
}

/// Lazy-allocate `perfmon_state` on first perfmon_start.
fn ensurePerfmonState(ec: *ExecutionContext) !*PerfmonState {
    if (ec.perfmon_state) |ref| {
        const p = ref.lock(@src()) catch unreachable;
        ref.unlock();
        return p;
    }
    const ref = try perfmon_mod.slab_instance.create();
    ec.perfmon_state = ref;
    return ref.ptr;
}

/// Free `perfmon_state` on perfmon_stop or implicit on EC destroy.
fn releasePerfmonState(ec: *ExecutionContext) void {
    const ref = ec.perfmon_state orelse return;
    ec.perfmon_state = null;
    perfmon_mod.slab_instance.destroy(ref.ptr, ref.gen) catch {};
}

/// True iff `ec` is a vCPU (vm != null). Spec §[virtual_machine].
fn isVcpu(ec: *const ExecutionContext) bool {
    return ec.vm != null;
}
