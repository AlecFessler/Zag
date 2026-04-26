const zag = @import("zag");

const errors = zag.syscall.errors;
const futex = zag.sched.futex;
const paging = zag.arch.dispatch.paging;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const PAddr = zag.memory.address.PAddr;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VAddr = zag.memory.address.VAddr;

const MAX_PAIRS: usize = 63;

/// Resolve `vaddr` in `caller`'s capability domain to a physical address.
/// Returns null when the address is unmapped. Holds the domain `_gen_lock`
/// for the duration of the walk so the page tables cannot be torn down by
/// a concurrent domain delete mid-translation.
fn resolveCallerVa(caller: *ExecutionContext, vaddr: u64) ?PAddr {
    const dom = caller.domain.lock(@src()) catch return null;
    defer caller.domain.unlock();
    return paging.resolveVaddr(dom.addr_space_root, VAddr.fromInt(vaddr));
}

/// Read `fut_wait_max` (slot-0 self-handle field0 bits 32-37). Stub —
/// real reader lives in capdom.capability_domain alongside the other
/// ceiling helpers.
fn readSelfFutWaitMax(domain_ref: SlabRef(CapabilityDomain)) u8 {
    _ = domain_ref;
    @panic("not implemented");
}

/// Read the slot-0 self-handle `fut_wake` cap bit. Stub — real reader
/// lives in capdom.capability_domain.
fn readSelfHasFutWake(domain_ref: SlabRef(CapabilityDomain)) bool {
    _ = domain_ref;
    @panic("not implemented");
}

/// Blocks while every `(addr, expected)` pair satisfies `*addr ==
/// expected`. Returns when any pair has `*addr != expected` (either at
/// call entry or after a wake), when any watched address is woken via
/// `futex_wake`, or on timeout.
///
/// ```
/// futex_wait_val([1] timeout_ns, [2 + 2i] addr, [2 + 2i + 1] expected) -> [1] addr
///   syscall_num = 43
///
///   syscall word bits 12-19: N (1..63)
///
///   [1] timeout_ns: 0 = non-blocking, u64::MAX = indefinite, otherwise nanoseconds
///   [2 + 2i] addr: 8-byte-aligned user address in the caller's domain
///   [2 + 2i + 1] expected: u64 expected value at addr
///
///   for i in 0..N-1.
/// ```
///
/// Self-handle requirement: `fut_wait_max >= 1`. The call's `N` must not
/// exceed `fut_wait_max`.
///
/// [test 01] returns E_PERM if the caller's self-handle has `fut_wait_max = 0`.
/// [test 02] returns E_INVAL if N is 0 or N > 63.
/// [test 03] returns E_INVAL if N exceeds the caller's self-handle `fut_wait_max`.
/// [test 04] returns E_INVAL if any addr is not 8-byte aligned.
/// [test 05] returns E_BADADDR if any addr is not a valid user address in the caller's domain.
/// [test 06] returns E_TIMEOUT if the timeout expires before any pair's `addr != expected` condition is met and before any watched address is woken.
/// [test 07] on entry, when any pair's current `*addr != expected`, returns immediately with `[1]` set to that addr.
/// [test 08] when another EC calls `futex_wake` on any watched addr, returns with `[1]` set to that addr (caller re-checks the value to determine whether the condition is actually met or the wake was spurious).
pub fn futexWaitVal(caller: *anyopaque, timeout_ns: u64, pairs: []const u64) i64 {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));

    if (pairs.len == 0 or (pairs.len & 1) != 0) return errors.E_INVAL;
    const n = pairs.len / 2;
    if (n == 0 or n > MAX_PAIRS) return errors.E_INVAL;

    const fut_wait_max = readSelfFutWaitMax(ec.domain);
    if (fut_wait_max == 0) return errors.E_PERM;
    if (n > fut_wait_max) return errors.E_INVAL;

    var addrs: [MAX_PAIRS]PAddr = undefined;
    var expected: [MAX_PAIRS]u64 = undefined;
    var i: usize = 0;
    while (i < n) {
        const va = pairs[i * 2];
        if ((va & 7) != 0) return errors.E_INVAL;
        addrs[i] = resolveCallerVa(ec, va) orelse return errors.E_BADADDR;
        expected[i] = pairs[i * 2 + 1];
        i += 1;
    }

    return futex.waitVal(addrs[0..n], expected[0..n], n, timeout_ns, @ptrCast(ec));
}

/// Blocks while every `(addr, target)` pair satisfies `*addr != target`.
/// Returns when any pair has `*addr == target` (at call entry or after a
/// wake), when any watched address is woken via `futex_wake`, or on
/// timeout.
///
/// ```
/// futex_wait_change([1] timeout_ns, [2 + 2i] addr, [2 + 2i + 1] target) -> [1] addr
///   syscall_num = 44
///
///   syscall word bits 12-19: N (1..63)
///
///   [1] timeout_ns: 0 = non-blocking, u64::MAX = indefinite, otherwise nanoseconds
///   [2 + 2i] addr: 8-byte-aligned user address in the caller's domain
///   [2 + 2i + 1] target: u64 target value at addr
///
///   for i in 0..N-1.
/// ```
///
/// Self-handle requirement: `fut_wait_max >= 1`. The call's `N` must not
/// exceed `fut_wait_max`.
///
/// [test 01] returns E_PERM if the caller's self-handle has `fut_wait_max = 0`.
/// [test 02] returns E_INVAL if N is 0 or N > 63.
/// [test 03] returns E_INVAL if N exceeds the caller's self-handle `fut_wait_max`.
/// [test 04] returns E_INVAL if any addr is not 8-byte aligned.
/// [test 05] returns E_BADADDR if any addr is not a valid user address in the caller's domain.
/// [test 06] returns E_TIMEOUT if the timeout expires before any pair's `addr == target` condition is met and before any watched address is woken.
/// [test 07] on entry, when any pair's current `*addr == target`, returns immediately with `[1]` set to that addr.
/// [test 08] when another EC calls `futex_wake` on any watched addr, returns with `[1]` set to that addr (caller re-checks the value to determine whether the condition is actually met or the wake was spurious).
pub fn futexWaitChange(caller: *anyopaque, timeout_ns: u64, pairs: []const u64) i64 {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));

    if (pairs.len == 0 or (pairs.len & 1) != 0) return errors.E_INVAL;
    const n = pairs.len / 2;
    if (n == 0 or n > MAX_PAIRS) return errors.E_INVAL;

    const fut_wait_max = readSelfFutWaitMax(ec.domain);
    if (fut_wait_max == 0) return errors.E_PERM;
    if (n > fut_wait_max) return errors.E_INVAL;

    var addrs: [MAX_PAIRS]PAddr = undefined;
    var targets: [MAX_PAIRS]u64 = undefined;
    var i: usize = 0;
    while (i < n) {
        const va = pairs[i * 2];
        if ((va & 7) != 0) return errors.E_INVAL;
        addrs[i] = resolveCallerVa(ec, va) orelse return errors.E_BADADDR;
        targets[i] = pairs[i * 2 + 1];
        i += 1;
    }

    // The current sched.futex.waitChange takes only addrs; the per-pair
    // target compare from the spec is part of step 5's futex rework.
    _ = targets;
    return futex.waitChange(addrs[0..n], n, timeout_ns, @ptrCast(ec));
}

/// Wakes up to `count` ECs blocked in `futex_wait_val` or
/// `futex_wait_change` on the given address. Wake order is
/// priority-ordered.
///
/// ```
/// futex_wake([1] addr, [2] count) -> [1] woken
///   syscall_num = 45
///
///   [1] addr: 8-byte-aligned user address in the caller's domain
///   [2] count: maximum number of ECs to wake
/// ```
///
/// Self-handle cap required: `fut_wake`.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `fut_wake`.
/// [test 02] returns E_INVAL if [1] addr is not 8-byte aligned.
/// [test 03] returns E_BADADDR if [1] addr is not a valid user address in the caller's domain.
/// [test 04] on success, [1] is the number of ECs actually woken (0..count).
pub fn futexWake(caller: *anyopaque, addr: u64, count: u64) i64 {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));

    if ((addr & 7) != 0) return errors.E_INVAL;
    if (!readSelfHasFutWake(ec.domain)) return errors.E_PERM;

    const paddr = resolveCallerVa(ec, addr) orelse return errors.E_BADADDR;
    const woken = futex.wake(paddr, @truncate(count));
    return @intCast(woken);
}
