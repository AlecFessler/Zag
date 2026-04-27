const zag = @import("zag");

const arch = zag.arch.dispatch;
const capability = zag.caps.capability;
const capability_domain = zag.capdom.capability_domain;
const errors = zag.syscall.errors;
const execution_context = zag.sched.execution_context;
const scheduler = zag.sched.scheduler;

const CapabilityDomain = capability_domain.CapabilityDomain;
const CapabilityDomainCaps = capability_domain.CapabilityDomainCaps;
const EcCaps = execution_context.EcCaps;
const ExecutionContext = execution_context.ExecutionContext;
const IdcCaps = capability_domain.IdcCaps;
const Priority = execution_context.Priority;
const VAddr = zag.memory.address.VAddr;
const Word0 = capability.Word0;

/// `caps` argument layout for `create_execution_context`: bits 0-33 valid
/// (caller-caps + target-caps + 2-bit priority); bits 34-63 reserved.
const CREATE_EC_CAPS_MASK: u64 = 0x0000_0003_FFFF_FFFF;

/// Bit offset of the priority field within the create_ec caps word.
const CREATE_EC_PRIORITY_SHIFT: u6 = 32;

/// 2-bit priority field width.
const PRIORITY_MASK: u64 = 0b11;

/// Slot 0 of every domain holds the self-handle whose cap word carries
/// `crec`, `pmu`, and the `pri` ceiling.
const SELF_HANDLE_SLOT: u12 = 0;

/// Reserved-bit mask for `new_priority` argument of `priority` syscall —
/// only bits 0-1 are valid.
const PRIORITY_ARG_MASK: u64 = 0b11;

/// Creates a new execution context either in the caller's own domain or
/// in a target domain referenced by an IDC handle.
///
/// ```
/// create_execution_context([1] caps, [2] entry, [3] stack_pages, [4] target, [5] vm_handle, [6] affinity)
///   -> [1] handle
///   syscall_num = 7
///
///   [1] caps: u64 packed as
///     bits  0-15: caps          — caps on the EC handle returned to the caller
///     bits 16-31: target_caps   — caps on the EC handle inserted into target's table
///                                 (ignored when target = self)
///     bits 32-33: priority      — scheduling priority, 0-3, bounded by caller's priority ceiling
///     bits 34-63: _reserved
///
///   [2] entry:        instruction pointer where the EC begins execution
///   [3] stack_pages:  number of stack pages the kernel allocates in the target's address space;
///                     kernel installs unmapped guard pages above and below the stack
///   [4] target:       0 = self, else IDC handle with crec cap to the target domain
///   [5] affinity:     64-bit core mask; bit N = 1 allows the EC to run on core N.
///                     0 = any core (kernel chooses)
/// ```
///
/// Caps required:
/// - Caller's self-handle must always have `crec`.
/// - If `[4] != 0`: the IDC handle in `[4]` must additionally have `crec`.
///
/// The kernel allocates `[3]` pages of stack in the target's address space
/// with unmapped guard pages above and below to catch overflow and
/// underflow. The EC begins executing at `[2] entry` with the stack
/// pointer set to the top of the allocated stack.
///
/// Returns E_NOMEM if insufficient kernel memory; returns E_NOSPC if the
/// target's address space has insufficient contiguous space for the
/// stack; returns E_FULL if the caller's handle table has no free slot,
/// or if `[4]` is nonzero and the target domain's handle table is full.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `crec`.
/// [test 02] returns E_PERM if [4] is nonzero and [4] lacks `crec`.
/// [test 03] returns E_PERM if [4] is 0 (target = self) and caps is not a subset of self's `ec_inner_ceiling`.
/// [test 04] returns E_PERM if [4] is nonzero and caps is not a subset of the target domain's `ec_outer_ceiling`.
/// [test 05] returns E_PERM if [4] is nonzero and target_caps is not a subset of the target domain's `ec_inner_ceiling`.
/// [test 06] returns E_PERM if priority exceeds the caller's priority ceiling.
/// [test 07] returns E_BADCAP if [4] is nonzero and not a valid IDC handle.
/// [test 08] returns E_INVAL if [3] stack_pages is 0.
/// [test 09] returns E_INVAL if [5] affinity has bits set outside the system's core count.
/// [test 10] returns E_INVAL if any reserved bits are set in [1].
/// [test 11] on success, the caller receives an EC handle with caps = `[1].caps`.
/// [test 12] on success, when [4] is nonzero, the target domain also receives a handle with caps = `[1].target_caps`.
/// [test 13] on success, the EC's priority is set to `[1].priority`.
/// [test 14] on success, the EC's affinity is set to `[5]`.
pub fn createExecutionContext(
    caller: *anyopaque,
    caps: u64,
    entry: u64,
    stack_pages: u64,
    target: u64,
    vm_handle: u64,
    affinity_mask: u64,
) i64 {
    _ = vm_handle;

    if (caps & ~CREATE_EC_CAPS_MASK != 0) return errors.E_INVAL;
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;
    if (stack_pages == 0) return errors.E_INVAL;

    const requested_priority: u2 = @intCast((caps >> CREATE_EC_PRIORITY_SHIFT) & PRIORITY_MASK);

    // Affinity 0 is the "any core" sentinel and bypasses the per-bit
    // core-count check; otherwise every set bit must name a real core.
    if (affinity_mask != 0) {
        const cores = arch.smp.coreCount();
        if (cores < 64) {
            const valid_mask: u64 = (@as(u64, 1) << @intCast(cores)) - 1;
            if (affinity_mask & ~valid_mask != 0) return errors.E_INVAL;
        }
    }

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;

    const self_caps_word = Word0.caps(cd.user_table[SELF_HANDLE_SLOT].word0);
    const self_caps: CapabilityDomainCaps = @bitCast(self_caps_word);
    if (!self_caps.crec) {
        cd_ref.unlock();
        return errors.E_PERM;
    }
    if (requested_priority > self_caps.pri) {
        cd_ref.unlock();
        return errors.E_PERM;
    }

    // Caller's `ec_inner_ceiling` lives in self-handle field0 bits 0-7
    // (spec §[capability_domain] field0 layout) and bounds the basic
    // EcCap rights at bits 0-7 (move/copy/saff/spri/term/susp/read/
    // write). EcCap bits 8-9 (`restart_policy`) are bounded separately
    // by `restart_policy_ceiling`; bits 10-12 (`bind`/`rebind`/
    // `unbind`) carry their own runtime gates in
    // bind_event_route/clear_event_route and are not constrained at
    // mint time. Test 03: when target=0 the new EC handle is minted in
    // the caller's own domain, so its caps[0..7] must be a subset of
    // `ec_inner_ceiling`.
    const new_caps: u16 = @truncate(caps & 0xFFFF);
    const target_caps: u16 = @truncate((caps >> 16) & 0xFFFF);
    const ec_inner_ceiling: u8 = @truncate(cd.user_table[SELF_HANDLE_SLOT].field0 & 0xFF);

    if (target == 0) {
        const new_caps_low: u8 = @truncate(new_caps & 0xFF);
        if (new_caps_low & ~ec_inner_ceiling != 0) {
            cd_ref.unlock();
            return errors.E_PERM;
        }
    }

    if (target != 0) {
        const idc_slot: u12 = @truncate(target);
        if (capability.resolveHandleOnDomain(cd, idc_slot, .capability_domain) == null) {
            cd_ref.unlock();
            return errors.E_BADCAP;
        }
        const idc_caps: IdcCaps = @bitCast(Word0.caps(cd.user_table[idc_slot].word0));
        if (!idc_caps.crec) {
            cd_ref.unlock();
            return errors.E_PERM;
        }
    }

    // Self-target success path: allocate the EC bound to the caller's
    // domain and mint a handle in that same domain with caps =
    // caps[0..15]. IDC-target paths still await per-domain handle-table
    // resolution against the target domain's ceilings (tests 04/05/12)
    // and remain stubbed below.
    if (target == 0) {
        _ = target_caps;
        const priority_enum: Priority = @enumFromInt(requested_priority);
        const new_ec = execution_context.allocExecutionContext(
            cd,
            VAddr.fromInt(entry),
            @intCast(stack_pages),
            affinity_mask,
            priority_enum,
            null,
            null,
        ) catch {
            cd_ref.unlock();
            return errors.E_NOMEM;
        };

        const slot = capability_domain.mintHandle(
            cd,
            .{
                .ptr = new_ec,
                .gen = @intCast(new_ec._gen_lock.currentGen()),
            },
            .execution_context,
            new_caps,
            0,
            0,
        ) catch {
            cd_ref.unlock();
            return errors.E_FULL;
        };

        // Field0/field1 carry the kernel-mutable priority/affinity
        // snapshot per §[execution_context]. Spec field0 bits 0-1 =
        // priority, field1 bits 0-63 = affinity mask.
        cd.user_table[slot].field0 = @intFromEnum(priority_enum);
        cd.user_table[slot].field1 = affinity_mask;

        cd_ref.unlock();
        // Spec §[error_codes]: a successful create_* returns the packed
        // Word0 so the type tag in bits 12-15 disambiguates from the
        // 1..15 error range.
        return @intCast(Word0.pack(slot, .execution_context, new_caps));
    }

    cd_ref.unlock();

    return execution_context.createExecutionContext(
        ec,
        caps,
        entry,
        stack_pages,
        target,
        affinity_mask,
    );
}

/// Returns the handle in the caller's table that references the calling
/// execution context. Pure lookup — no handle is inserted, minted, or
/// modified, and no authority is granted. By the at-most-one invariant,
/// there is at most one such handle.
///
/// ```
/// self() -> [1] handle
///   syscall_num = 8
/// ```
///
/// [test 01] returns E_NOENT if no handle in the caller's table references the calling execution context.
/// [test 02] on success, [1] is a handle in the caller's table whose resolved capability references the calling execution context.
pub fn self(caller: *anyopaque) i64 {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    return execution_context.self(ec);
}

/// Terminates the target execution context.
///
/// ```
/// terminate([1] target) -> void
///   syscall_num = 9
///
///   [1] target: EC handle
/// ```
///
/// EC cap required: `term`.
///
/// Termination atomically destroys the EC. Handles referencing it in any
/// capability domain become stale; a syscall invoked with a stale handle
/// returns `E_TERM` and the stale handle is removed from the caller's
/// table on the same call.
///
/// Termination also clears the kernel-held event routes bound to the EC
/// (§[event_route]) and marks any reply handles whose suspended sender
/// was the terminated EC such that subsequent operations on those reply
/// handles return `E_ABANDONED`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid EC handle.
/// [test 02] returns E_PERM if [1] does not have the `term` cap.
/// [test 03] returns E_INVAL if any reserved bits are set in [1].
/// [test 04] on success, the target EC stops executing.
/// [test 05] on success, syscalls invoked with any handle to the terminated EC return E_TERM and remove that handle from the caller's table on the same call.
/// [test 06] on success, no further events generated by the terminated EC are delivered to any port previously bound by an event_route from that EC.
/// [test 07] on success, reply handles whose suspended sender was the terminated EC return E_ABANDONED on subsequent operations.
/// [test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn terminate(caller: *anyopaque, target: u64) i64 {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;

    const slot: u12 = @truncate(target);
    if (capability.resolveHandleOnDomain(cd, slot, .execution_context) == null) {
        cd_ref.unlock();
        return errors.E_BADCAP;
    }

    const ec_caps: EcCaps = @bitCast(Word0.caps(cd.user_table[slot].word0));
    cd_ref.unlock();
    if (!ec_caps.term) return errors.E_PERM;

    return execution_context.terminate(ec, target);
}

/// Yields the calling EC's timeslice. With `[1] = 0`, the scheduler
/// selects the next EC to run. With `[1]` a valid handle to a runnable
/// EC, that EC is scheduled next; if it is not runnable, the scheduler
/// selects.
///
/// ```
/// yield([1] target) -> void
///   syscall_num = 10
///
///   [1] target: 0 = yield to scheduler; else an EC handle to yield to
/// ```
///
/// No cap required.
///
/// [test 01] returns E_BADCAP if [1] is nonzero and not a valid EC handle.
/// [test 02] returns E_INVAL if any reserved bits are set in [1].
/// [test 03] on success, when [1] is a valid handle to a runnable EC, an observable side effect performed by the target EC (e.g., a write to shared memory) is visible to the caller before the caller's next syscall returns.
/// [test 04] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn yield(caller: *anyopaque, target: u64) i64 {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));

    if (target == 0) {
        scheduler.yieldTo(null);
        return 0;
    }

    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;
    const slot: u12 = @truncate(target);
    const entry = capability.resolveHandleOnDomain(cd, slot, .execution_context) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };
    const ref = capability.typedRef(ExecutionContext, entry.*) orelse {
        cd_ref.unlock();
        return errors.E_BADCAP;
    };
    cd_ref.unlock();

    // Resolve the target EC pointer under its own gen lock just long
    // enough to hand it off — `yieldTo` consumes a stable pointer.
    const target_ec = ref.lock(@src()) catch return errors.E_TERM;
    ref.unlock();
    scheduler.yieldTo(target_ec);
    return 0;
}

/// Sets the target execution context's priority. The new priority applies
/// to subsequent scheduling, port event delivery, and futex wake
/// ordering. If the target is currently suspended on a port or waiting on
/// a futex, the new priority takes effect immediately and reorders the
/// target into the appropriate priority bucket (this is the mechanism
/// priority inheritance is built on).
///
/// ```
/// priority([1] target, [2] new_priority) -> void
///   syscall_num = 11
///
///   [1] target: EC handle
///   [2] new_priority: 0..3
/// ```
///
/// EC cap required on [1]: `spri`. `[2]` must not exceed the caller's
/// self-handle `pri`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid EC handle.
/// [test 02] returns E_PERM if [1] does not have the `spri` cap.
/// [test 03] returns E_PERM if [2] exceeds the caller's self-handle `pri`.
/// [test 04] returns E_INVAL if [2] is greater than 3.
/// [test 05] returns E_INVAL if any reserved bits are set in [1].
/// [test 06] on success, when two ECs are blocked in `futex_wait_val` on the same address and a `futex_wake` is issued, the EC whose priority was last set higher via `priority` is woken first; the same ordering applies to `recv` selection when the two ECs are both queued senders on the same port.
/// [test 07] on success, when the target is suspended on a port or waiting on a futex, [2] takes effect on the target's next port event delivery and futex wake.
/// [test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn priority(caller: *anyopaque, target: u64, new_priority: u64) i64 {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;
    if (new_priority & ~PRIORITY_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;

    const slot: u12 = @truncate(target);
    if (capability.resolveHandleOnDomain(cd, slot, .execution_context) == null) {
        cd_ref.unlock();
        return errors.E_BADCAP;
    }

    const ec_caps: EcCaps = @bitCast(Word0.caps(cd.user_table[slot].word0));
    const self_caps: CapabilityDomainCaps = @bitCast(Word0.caps(cd.user_table[SELF_HANDLE_SLOT].word0));
    cd_ref.unlock();

    if (!ec_caps.spri) return errors.E_PERM;
    if (new_priority > self_caps.pri) return errors.E_PERM;

    return execution_context.setPriority(ec, target, new_priority);
}

/// Sets the target execution context's CPU affinity mask.
///
/// ```
/// affinity([1] target, [2] new_affinity) -> void
///   syscall_num = 12
///
///   [1] target: EC handle
///   [2] new_affinity: 64-bit core mask. 0 = kernel picks any core.
///                     Otherwise, bit N = 1 allows the target EC to run on core N;
///                     bit N must only be set for cores the system actually has.
/// ```
///
/// EC cap required on [1]: `saff`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid EC handle.
/// [test 02] returns E_PERM if [1] does not have the `saff` cap.
/// [test 03] returns E_INVAL if any bit set in [2] corresponds to a core the system does not have.
/// [test 04] returns E_INVAL if any reserved bits are set in [1].
/// [test 05] on success, the target EC's affinity is set to [2].
/// [test 06] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn affinity(caller: *anyopaque, target: u64, new_affinity: u64) i64 {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;

    if (new_affinity != 0) {
        const cores = arch.smp.coreCount();
        if (cores < 64) {
            const valid_mask: u64 = (@as(u64, 1) << @intCast(cores)) - 1;
            if (new_affinity & ~valid_mask != 0) return errors.E_INVAL;
        }
    }

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;

    const slot: u12 = @truncate(target);
    if (capability.resolveHandleOnDomain(cd, slot, .execution_context) == null) {
        cd_ref.unlock();
        return errors.E_BADCAP;
    }

    const ec_caps: EcCaps = @bitCast(Word0.caps(cd.user_table[slot].word0));
    cd_ref.unlock();
    if (!ec_caps.saff) return errors.E_PERM;

    return execution_context.setAffinity(ec, target, new_affinity);
}

/// Queries system PMU capabilities.
///
/// ```
/// perfmon_info() -> [1] caps_word, [2] supported_events
///   syscall_num = 13
///
///   [1] caps_word: u64 packed as
///     bits 0-7: num_counters
///     bit 8:    overflow_support
///     bits 9-63: _reserved
///
///   [2] supported_events: u64 bitmask
/// ```
///
/// Self-handle cap required: `pmu`.
///
/// Supported event bits:
///
/// | Bit | Event |
/// |---|---|
/// | 0 | cycles |
/// | 1 | instructions |
/// | 2 | cache_references |
/// | 3 | cache_misses |
/// | 4 | branch_instructions |
/// | 5 | branch_misses |
/// | 6 | bus_cycles |
/// | 7 | stalled_cycles_frontend |
/// | 8 | stalled_cycles_backend |
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `pmu`.
/// [test 02] [1] bits 0-7 contain the number of available PMU counters.
/// [test 03] [1] bit 8 is set when the hardware supports counter overflow events.
/// [test 04] [2] is a bitmask of supported events indexed by the table above.
pub fn perfmonInfo(caller: *anyopaque) i64 {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;

    const self_caps: CapabilityDomainCaps = @bitCast(Word0.caps(cd.user_table[SELF_HANDLE_SLOT].word0));
    cd_ref.unlock();
    if (!self_caps.pmu) return errors.E_PERM;

    return execution_context.perfmonInfo(ec);
}

/// Starts hardware performance counters on the target EC.
///
/// ```
/// perfmon_start([1] target, [2] num_configs, [3 + 2i] config_event, [3 + 2i + 1] config_threshold) -> void
///   syscall_num = 14
///
///   [1] target:        EC handle
///   [2] num_configs:   N, the number of counter configs supplied
///   [3 + 2i] config_event: u64 packed as
///     bits 0-7: event index (per perfmon_info supported_events bitmask)
///     bit 8:    has_threshold
///     bits 9-63: _reserved
///   [3 + 2i + 1] config_threshold: u64 overflow threshold (used only when has_threshold = 1)
///
///   for i in 0..N-1.
/// ```
///
/// Self-handle cap required: `pmu`.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `pmu`.
/// [test 02] returns E_BADCAP if [1] is not a valid EC handle.
/// [test 03] returns E_INVAL if [2] is 0 or exceeds num_counters.
/// [test 04] returns E_INVAL if any config's event is not in supported_events.
/// [test 05] returns E_INVAL if any config has has_threshold = 1 but the hardware does not support overflow.
/// [test 06] returns E_INVAL if any reserved bits are set in any config_event.
/// [test 07] returns E_BUSY if [1] is not the calling EC and not currently suspended.
/// [test 08] on success, a subsequent `perfmon_read` on the target EC returns nonzero values in vregs `[1..2]` after the target EC has executed enough work to register the configured events.
/// [test 09] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn perfmonStart(
    caller: *anyopaque,
    target: u64,
    num_configs: u64,
    configs: []const u64,
) i64 {
    const ec = checkPmuTarget(caller, target) catch |e| return pmuErrorCode(e);
    const info = arch.pmu.pmuGetInfo();
    if (num_configs == 0 or num_configs > info.num_counters) return errors.E_INVAL;
    const num_configs_u8: u8 = @intCast(num_configs);
    return execution_context.perfmonStart(ec, target, num_configs_u8, configs);
}

/// Reads the current counter values from the target EC.
///
/// ```
/// perfmon_read([1] target) -> [1..num_counters] counter_values, [num_counters + 1] timestamp
///   syscall_num = 15
///
///   [1] target: EC handle
/// ```
///
/// Self-handle cap required: `pmu`.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `pmu`.
/// [test 02] returns E_BADCAP if [1] is not a valid EC handle.
/// [test 03] returns E_INVAL if perfmon was not started on the target EC.
/// [test 04] returns E_BUSY if [1] is not the calling EC and not currently suspended.
/// [test 05] on success, [1..num_counters] contain the current counter values for the active counters.
/// [test 06] on success, [num_counters + 1] is a u64 nanosecond timestamp strictly greater than the timestamp from any prior `perfmon_read` on the same target EC, and each counter value is greater than or equal to the value returned by the prior `perfmon_read` on that target.
/// [test 07] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn perfmonRead(caller: *anyopaque, target: u64) i64 {
    const ec = checkPmuTarget(caller, target) catch |e| return pmuErrorCode(e);
    return execution_context.perfmonRead(ec, target);
}

/// Stops counting on the target EC and releases PMU state.
///
/// ```
/// perfmon_stop([1] target) -> void
///   syscall_num = 16
///
///   [1] target: EC handle
/// ```
///
/// Self-handle cap required: `pmu`.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `pmu`.
/// [test 02] returns E_BADCAP if [1] is not a valid EC handle.
/// [test 03] returns E_INVAL if perfmon was not started on the target EC.
/// [test 04] returns E_BUSY if [1] is not the calling EC and not currently suspended.
/// [test 05] on success, a subsequent `perfmon_read` on the target EC returns E_INVAL (perfmon was not started).
/// [test 06] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn perfmonStop(caller: *anyopaque, target: u64) i64 {
    const ec = checkPmuTarget(caller, target) catch |e| return pmuErrorCode(e);
    return execution_context.perfmonStop(ec, target);
}

/// Failure modes for `checkPmuTarget`. Mapped to spec errors via
/// `pmuErrorCode`.
const PmuResolveError = error{
    NoPmuCap,
    BadHandle,
    BadArg,
};

/// Shared cap + handle gate for `perfmon_start`/`read`/`stop`. Verifies
/// the target handle bits, the caller's `pmu` self-cap, and that the
/// handle resolves to an EC. Returns the *caller* EC — the inner sched
/// entry points expect the calling EC, not the target.
fn checkPmuTarget(caller: *anyopaque, target: u64) PmuResolveError!*ExecutionContext {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return error.BadArg;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return error.BadHandle;

    const self_caps: CapabilityDomainCaps = @bitCast(Word0.caps(cd.user_table[SELF_HANDLE_SLOT].word0));
    if (!self_caps.pmu) {
        cd_ref.unlock();
        return error.NoPmuCap;
    }

    const slot: u12 = @truncate(target);
    if (capability.resolveHandleOnDomain(cd, slot, .execution_context) == null) {
        cd_ref.unlock();
        return error.BadHandle;
    }
    cd_ref.unlock();

    return ec;
}

fn pmuErrorCode(e: PmuResolveError) i64 {
    return switch (e) {
        error.NoPmuCap => errors.E_PERM,
        error.BadHandle => errors.E_BADCAP,
        error.BadArg => errors.E_INVAL,
    };
}
