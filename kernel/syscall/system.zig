const zag = @import("zag");

const cpu = zag.arch.dispatch.cpu;
const errors = zag.syscall.errors;
const smp = zag.arch.dispatch.smp;
const time = zag.arch.dispatch.time;

const CapabilityDomainCaps = zag.capdom.capability_domain.CapabilityDomainCaps;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const PowerAction = cpu.PowerAction;
const Word0 = zag.caps.capability.Word0;

/// Returns nanoseconds since boot.
///
/// ```
/// time_monotonic() -> [1] ns
///   syscall_num = 46
/// ```
///
/// No cap required.
///
/// [test 01] on success, [1] is a u64 nanosecond count strictly greater than the value returned by any prior call to `time_monotonic`.
pub fn timeMonotonic(caller: *anyopaque) i64 {
    _ = caller;
    return @bitCast(time.currentMonotonicNs());
}

/// Returns wall-clock time as nanoseconds since the Unix epoch.
///
/// ```
/// time_getwall() -> [1] ns_since_epoch
///   syscall_num = 47
/// ```
///
/// No cap required.
///
/// [test 02] after `time_setwall(X)` succeeds, a subsequent `time_getwall` returns a value within a small bounded delta of X.
pub fn timeGetwall(caller: *anyopaque) i64 {
    _ = caller;
    return @bitCast(time.readRtc());
}

/// Sets the wall-clock time to the given nanoseconds-since-epoch.
///
/// ```
/// time_setwall([1] ns_since_epoch) -> void
///   syscall_num = 48
///
///   [1] ns_since_epoch: new wall-clock value (nanoseconds since Unix epoch)
/// ```
///
/// Self-handle cap required: `setwall`.
///
/// [test 03] returns E_PERM if the caller's self-handle lacks `setwall`.
/// [test 04] returns E_INVAL if any reserved bits are set in [1].
/// [test 05] on success, a subsequent `time_getwall` returns a value within a small bounded delta of [1].
pub fn timeSetwall(caller: *anyopaque, ns_since_epoch: u64) i64 {
    // TODO: spec test 04 mentions reserved bits in [1], but the field is
    // documented as a full u64 ns_since_epoch with no published reserved
    // bit layout. Apply the mask once the layout is defined.
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.setwall) return errors.E_PERM;
    return time.writeRtc(ns_since_epoch);
}

/// Fills the requested number of vregs with cryptographically random
/// qwords.
///
/// ```
/// random() -> [1..count] qwords
///   syscall_num = 49
///
///   syscall word bits 12-19: count (1..127)
/// ```
///
/// No cap required.
///
/// [test 01] returns E_INVAL if count is 0 or count > 127.
/// [test 02] on success, vregs `[1..count]` contain qwords (the CSPRNG-source guarantee in the prose above is a kernel implementation contract, not a black-box-testable assertion).
pub fn random(caller: *anyopaque) i64 {
    _ = caller;
    // TODO: needs (a) syscall-word access to read `count` from bits
    // 12-19, and (b) a vreg-write helper to populate vregs [1..count].
    // Wire once the dispatch layer exposes both.
    return -1;
}

/// Returns system-wide capacity and capability information.
///
/// ```
/// info_system() -> [1] cores, [2] features, [3] total_phys_pages, [4] page_size_mask
///   syscall_num = 50
/// ```
///
/// No cap required.
///
/// Output:
/// - `[1]` cores: total online CPU core count
/// - `[2]` features: bitmask
///   - bit 0: hardware virtualization (Intel VMX or AMD SVM)
///   - bit 1: IOMMU
///   - bit 2: PMU
///   - bit 3: wide vector ISA (AVX-512 on x86-64, SVE on aarch64)
///   - bits 4-63: _reserved
/// - `[3]` total_phys_pages: total physical memory expressed in 4 KiB pages
/// - `[4]` page_size_mask: which physical page sizes the kernel can allocate
///   - bit 0: 4 KiB
///   - bit 1: 2 MiB
///   - bit 2: 1 GiB
///   - bits 3-63: _reserved
///
/// [test 01] on success, [1] equals the number of online CPU cores reported by the platform.
/// [test 02] on success, [3] equals the platform's total RAM divided by 4 KiB.
/// [test 03] on success, [4] bit 0 is set on every supported architecture.
pub fn infoSystem(caller: *anyopaque) i64 {
    _ = caller;
    // TODO: vregs [2]/[3]/[4] (features, total_phys_pages, page_size_mask)
    // need a vreg-write helper from the dispatch layer. Returning [1]
    // (cores) only for now.
    return @bitCast(smp.coreCount());
}

/// Returns information about a specific core.
///
/// ```
/// info_cores([1] core_id) -> [1] flags, [2] freq_hz, [3] vendor_model
///   syscall_num = 51
///
///   [1] on input: core id
/// ```
///
/// No cap required.
///
/// Output:
/// - `[1]` flags: bitmask
///   - bit 0: online
///   - bit 1: idle states supported
///   - bit 2: frequency scaling supported
///   - bits 3-63: _reserved
/// - `[2]` freq_hz: current frequency in Hz, 0 if unreadable
/// - `[3]` vendor_model: platform-defined packed identifier; layout follows the architecture vendor's encoding (e.g., x86 family/model/stepping, ARM IDR fields)
///
/// [test 04] returns E_INVAL if [1] core_id is greater than or equal to `info_system`'s `cores`.
/// [test 05] returns E_INVAL if any reserved bits are set in [1].
/// [test 06] on success, [1] flag bit 0 reflects whether the queried core is currently online.
pub fn infoCores(caller: *anyopaque, core_id: u64) i64 {
    _ = caller;
    // TODO: spec test 05 mentions reserved bits in [1], but the input is
    // a bare core_id with no published reserved layout. Apply the mask
    // once the layout is defined.
    if (core_id >= smp.coreCount()) return errors.E_INVAL;
    // TODO: vregs [2]/[3] (freq_hz, vendor_model) need a vreg-write
    // helper from the dispatch layer. Returning [1] (flags) only for now.
    // bit 0 = online; flags 1/2 (idle/freq-scaling supported) need
    // per-core capability probes that aren't yet exposed.
    const flags: u64 = 0b1;
    return @bitCast(flags);
}

/// Performs an immediate orderly system poweroff. Does not return on
/// success.
///
/// ```
/// power_shutdown() -> void
///   syscall_num = 52
/// ```
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `power`.
pub fn powerShutdown(caller: *anyopaque) i64 {
    return doPowerAction(caller, .shutdown);
}

/// Performs a warm system reboot. Does not return on success.
///
/// ```
/// power_reboot() -> void
///   syscall_num = 53
/// ```
///
/// [test 02] returns E_PERM if the caller's self-handle lacks `power`.
pub fn powerReboot(caller: *anyopaque) i64 {
    return doPowerAction(caller, .reboot);
}

/// Enters a system-wide low-power state at the requested depth. Returns
/// when the system wakes.
///
/// ```
/// power_sleep([1] depth) -> void
///   syscall_num = 54
///
///   [1] depth: 1 = sleep (S1/S3-equivalent), 3 = deep sleep (S4-equivalent), 4 = hibernate (S5-equivalent)
/// ```
///
/// [test 03] returns E_PERM if the caller's self-handle lacks `power`.
/// [test 04] returns E_INVAL if [1] is not 1, 3, or 4.
/// [test 05] returns E_NODEV if the platform does not support the requested sleep depth.
pub fn powerSleep(caller: *anyopaque, depth: u64) i64 {
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.power) return errors.E_PERM;
    const action: PowerAction = switch (depth) {
        1 => .sleep,
        3 => .hibernate,
        4 => .hibernate,
        else => return errors.E_INVAL,
    };
    return cpu.powerAction(action);
}

/// Turns the primary display off. Subsequent input wakes it.
///
/// ```
/// power_screen_off() -> void
///   syscall_num = 55
/// ```
///
/// [test 06] returns E_PERM if the caller's self-handle lacks `power`.
pub fn powerScreenOff(caller: *anyopaque) i64 {
    return doPowerAction(caller, .screen_off);
}

/// Sets the target frequency for a specific core in Hz.
///
/// ```
/// power_set_freq([1] core_id, [2] hz) -> void
///   syscall_num = 56
///
///   [1] core_id: target core
///   [2] hz: target frequency in Hz; 0 = let the kernel pick
/// ```
///
/// [test 07] returns E_PERM if the caller's self-handle lacks `power`.
/// [test 08] returns E_INVAL if [1] is greater than or equal to `info_system`'s `cores`.
/// [test 09] returns E_NODEV if the queried core does not support frequency scaling (per `info_cores` flag bit 2).
/// [test 10] returns E_INVAL if [2] is nonzero and outside the platform's supported frequency range.
/// [test 11] on success, a subsequent `info_cores([1])` reports a `freq_hz` consistent with the requested target (within hardware tolerance).
pub fn powerSetFreq(caller: *anyopaque, core_id: u64, hz: u64) i64 {
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.power) return errors.E_PERM;
    if (core_id >= smp.coreCount()) return errors.E_INVAL;
    // TODO: per-core frequency-scaling capability probe (spec test 09)
    // and per-platform frequency-range bounds check (spec test 10) are
    // not yet exposed by the arch dispatch. The current backend ignores
    // core_id and operates on the local core only.
    return cpu.cpuPowerAction(.set_freq, hz);
}

/// Sets the idle policy for a specific core.
///
/// ```
/// power_set_idle([1] core_id, [2] policy) -> void
///   syscall_num = 57
///
///   [1] core_id: target core
///   [2] policy: 0 = busy-poll (no idle entry), 1 = halt only (shallow), 2 = deepest available c-state
/// ```
///
/// [test 12] returns E_PERM if the caller's self-handle lacks `power`.
/// [test 13] returns E_INVAL if [1] is greater than or equal to `info_system`'s `cores`.
/// [test 14] returns E_NODEV if the queried core does not support idle states (per `info_cores` flag bit 1).
/// [test 15] returns E_INVAL if [2] is greater than 2.
pub fn powerSetIdle(caller: *anyopaque, core_id: u64, policy: u64) i64 {
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.power) return errors.E_PERM;
    if (core_id >= smp.coreCount()) return errors.E_INVAL;
    if (policy > 2) return errors.E_INVAL;
    // TODO: per-core idle-state capability probe (spec test 14) is not
    // yet exposed by the arch dispatch. The current backend ignores
    // core_id and operates on the local core only.
    return cpu.cpuPowerAction(.set_idle, policy);
}

// ── Helpers ──────────────────────────────────────────────────────────

fn doPowerAction(caller: *anyopaque, action: PowerAction) i64 {
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.power) return errors.E_PERM;
    return cpu.powerAction(action);
}

/// Read the `cap` field from the caller domain's slot-0 self-handle.
/// Returns null if the underlying domain ref is stale (caller's domain
/// was torn down concurrently — should not happen in practice for an
/// in-syscall caller, but guards against UAF on the slab path).
fn readSelfCaps(caller: *anyopaque) ?CapabilityDomainCaps {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return null;
    defer cd_ref.unlock();
    const caps_bits = Word0.caps(cd.user_table[0].word0);
    return @bitCast(caps_bits);
}
