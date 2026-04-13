//! Generic `sys_info` syscall layer.
//!
//! Defines the observable `SysInfo` / `CoreInfo` types and implements
//! `sysSysInfo`. All architecture-specific reads (current frequency,
//! temperature, C-state) are delegated to `arch.getCoreFreq` /
//! `arch.getCoreTemp` / `arch.getCoreState`; this file contains zero
//! x86-specific state or MSR references.
//!
//! Public contract is in spec §2.15 (observable types and accounting
//! window semantics) and spec §4.55 (the syscall itself). Internals are
//! documented in systems.md §sysinfo "System Info Internals".

const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const scheduler = zag.sched.scheduler;

const Process = zag.proc.process.Process;
const VAddr = zag.memory.address.VAddr;

const E_OK = errors.E_OK;
const E_BADADDR = errors.E_BADADDR;

// ── Observable types (spec §2.15) ───────────────────────────────────────

/// System-wide static and dynamic properties. Written to `info_ptr` by
/// every `sys_info` call (spec §2.15.1–§2.15.3).
pub const SysInfo = extern struct {
    core_count: u64,
    mem_total: u64,
    mem_free: u64,
};

/// Per-core dynamic properties, one entry per core indexed by core ID
/// (see spec §2.15). Field order matches the spec's prose:
/// scheduler-accounting pair first, then the hardware-sampled triple.
///
/// Padding at the tail brings the struct to an 8-byte-aligned size so
/// `cores_ptr[i]` is naturally aligned and the extern layout is
/// deterministic across toolchains. The padding bytes are zeroed before
/// the entry is written to userspace so the ABI is clean.
pub const CoreInfo = extern struct {
    idle_ns: u64,
    busy_ns: u64,
    freq_hz: u64,
    temp_mc: u32,
    c_state: u8,
    _pad: [3]u8 = .{ 0, 0, 0 },
};

comptime {
    std.debug.assert(@sizeOf(SysInfo) == 24);
    // 8 + 8 + 8 + 4 + 1 + 3 = 32 bytes.
    std.debug.assert(@sizeOf(CoreInfo) == 32);
}

// ── Syscall entry point ─────────────────────────────────────────────────

/// §4.55 `sys_info(info_ptr, cores_ptr) → result`.
///
/// Two-call pattern:
///   1. First call with `cores_ptr = 0` obtains `SysInfo` (including
///      `core_count`). No per-core accounting is touched.
///   2. Subsequent calls with both pointers set obtain live per-core data
///      and reset each core's `idle_ns`/`busy_ns` atomically; the
///      interval between such calls is the accounting window.
///
/// Ordering for the two-pointer case, chosen to satisfy two independent
/// invariants from §4.55:
///
///   (a) **No partial `info_ptr` write on an `E_BADADDR` path** — if
///       `cores_ptr` is invalid the caller's `SysInfo` buffer must not
///       be touched (tested by §4.55.5).
///   (b) **No accounting loss on a late `info_ptr` write failure** — if
///       `info_ptr` looks valid up front but the write itself later
///       fails (e.g. a racing unmap between validation and commit), the
///       per-core `idle_ns`/`busy_ns` accounting must not have been
///       consumed yet.
///
/// To satisfy (a) we cannot commit `info_ptr` before we know the
/// `cores_ptr` range is writable, and `validateUserWritable` is a purely
/// symbolic range check — it does not walk the page tables, so a
/// partition-contained-but-unmapped pointer (e.g. address `1`) slips
/// through it. We therefore *probe* the `cores_ptr` range with
/// `probeUserWritable`, which faults in / resolves every page in the
/// range exactly the way `writeUser` would, but without the memcpy. If
/// that probe fails we return `E_BADADDR` before either write happens.
///
/// Once the probe succeeds, we write `info_ptr` before draining the
/// per-core accounting — that satisfies (b), because a late write
/// failure on `info_ptr` leaves the accounting untouched. Only after
/// both the probe and the info write succeed do we atomically drain each
/// core's `idle_ns`/`busy_ns`, sample the hardware triple, and write the
/// freshly assembled `CoreInfo` array into the (already-faulted-in)
/// `cores_ptr` pages. That final write is virtually guaranteed to
/// succeed because `probeUserWritable` has already populated the
/// mappings; if it still fails (another racing unmap), the accounting
/// window has already been consumed — the caller did receive `SysInfo`
/// and we have committed to the reset at that point. This is acceptable
/// for the rare late-page-out failure mode.
pub fn sysSysInfo(proc: *Process, info_ptr: u64, cores_ptr: u64) i64 {
    // §4.55.3: `info_ptr` must point to a writable region of
    // `sizeof(SysInfo)` bytes.
    const core_count = arch.coreCount();
    const info: SysInfo = .{
        .core_count = core_count,
        .mem_total = pmm.totalPageCount(),
        .mem_free = pmm.freePageCount(),
    };

    if (cores_ptr == 0) {
        // §4.55.4: write only `SysInfo`; never touch per-core accounting.
        if (!writeUser(proc, info_ptr, std.mem.asBytes(&info))) return E_BADADDR;
        return E_OK;
    }

    // §4.55.5: `cores_ptr` must point to a writable region of
    // `core_count * sizeof(CoreInfo)` bytes. Symbolic range check
    // first (catches wraparound / kernel-partition / null), then a
    // real demand-page walk via `probeUserWritable` so an in-partition
    // but unmapped pointer is rejected BEFORE `info_ptr` is written.
    // Without the probe, §4.55.5 can't be satisfied together with
    // §4.55.3's "no partial info_ptr write on E_BADADDR" invariant.
    const total_bytes = std.math.mul(u64, core_count, @sizeOf(CoreInfo)) catch
        return E_BADADDR;
    if (!validateUserWritable(cores_ptr, total_bytes)) return E_BADADDR;

    // Info pointer also has to be writable (§4.55.3). Symbolic check
    // only — the actual write below is allowed to race with a late
    // unmap, which bails cleanly without touching accounting.
    if (!validateUserWritable(info_ptr, @sizeOf(SysInfo))) return E_BADADDR;

    // Demand-page / resolve every page of the `cores_ptr` range without
    // writing. If any page fails to resolve, the pointer is bad and we
    // return E_BADADDR before `info_ptr` has been touched.
    if (!probeUserWritable(proc, cores_ptr, total_bytes)) return E_BADADDR;

    // Write `SysInfo` now. If a late page-out race causes this write
    // to fail, no accounting state has been touched yet and the syscall
    // bails with `E_BADADDR` cleanly. Only after this succeeds do we
    // commit to the per-core read-and-reset.
    if (!writeUser(proc, info_ptr, std.mem.asBytes(&info))) return E_BADADDR;

    // §4.55.6: read-and-reset the accounting pair, read the hardware
    // triple, and stamp one `CoreInfo` entry per core. The array is
    // assembled in a local buffer and bulk-copied into userspace in a
    // single pass to avoid interleaving per-core work with per-page
    // user-space demand faulting.
    //
    // Cap at the system-limit of 64 cores (spec §5 "Max
    // SysInfo.core_count"); this matches the scheduler's `MAX_CORES`.
    var entries: [MAX_CORES]CoreInfo = undefined;
    var i: u64 = 0;
    while (i < core_count and i < MAX_CORES) {
        const acct = scheduler.perCoreReadAndResetAccounting(i);
        entries[i] = .{
            .idle_ns = acct.idle_ns,
            .busy_ns = acct.busy_ns,
            .freq_hz = arch.getCoreFreq(i),
            .temp_mc = arch.getCoreTemp(i),
            .c_state = arch.getCoreState(i),
        };
        i += 1;
    }

    // If this final write fails (late page-out after up-front
    // validation), the accounting window has already been consumed —
    // the caller did receive `SysInfo` and we have committed to the
    // reset at that point.
    const cores_bytes = std.mem.sliceAsBytes(entries[0..@intCast(core_count)]);
    if (!writeUser(proc, cores_ptr, cores_bytes)) return E_BADADDR;

    return E_OK;
}

/// Upper bound on `core_count`; mirrors `sched.scheduler.MAX_CORES` and
/// the spec §5 "Max SysInfo.core_count" row. Used to size the local
/// `CoreInfo` buffer without pulling in a runtime allocation.
const MAX_CORES: u64 = 64;

// ── User-space validation / write helpers ──────────────────────────────
//
// Mirrors the helpers in `kernel/sched/pmu.zig` (`readUser`, `writeUser`).
// Duplicated here so the sysinfo layer has no cross-dependency on the
// PMU module.

/// Check that `[user_va, user_va + len)` is inside the user address
/// partition and does not wrap. Used by the early-fail path; the real
/// write-time fault still resolves via `writeUser` physmap walks.
fn validateUserWritable(user_va: u64, len: u64) bool {
    if (len == 0) return true;
    if (user_va == 0) return false;
    if (!address.AddrSpacePartition.user.contains(user_va)) return false;
    const end = std.math.add(u64, user_va, len) catch return false;
    if (!address.AddrSpacePartition.user.contains(end -| 1)) return false;
    return true;
}

/// Walk a user-space range page-by-page, demand-paging and resolving
/// each covered page the same way `writeUser` would, but without any
/// memcpy. Used by `sysSysInfo` to probe the `cores_ptr` range before
/// committing a write to `info_ptr` — the plain `validateUserWritable`
/// check only rejects wraparound / kernel-partition / null addresses,
/// so an in-partition but unmapped pointer would otherwise slip through
/// and allow a partial-write leak onto `info_ptr`. Returns `false` on
/// any of: zero address, partition boundary violation, wraparound, a
/// demand-page failure, or a post-demand-page resolve miss. After a
/// successful probe the range is guaranteed to have physical backing,
/// so the subsequent `writeUser` on the same range is almost always
/// infallible — a concurrent unmap between the probe and the write is
/// the only remaining failure mode.
fn probeUserWritable(proc: *Process, user_va: u64, len: u64) bool {
    if (len == 0) return true;
    if (user_va == 0) return false;
    if (!address.AddrSpacePartition.user.contains(user_va)) return false;
    const end = std.math.add(u64, user_va, len) catch return false;
    if (!address.AddrSpacePartition.user.contains(end -| 1)) return false;

    var remaining: usize = len;
    var dst_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = dst_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(dst_va), true, false) catch return false;
        _ = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return false;
        dst_va += chunk;
        remaining -= chunk;
    }
    return true;
}

/// Write `data` into the caller's address space via physmap, handling
/// cross-page boundaries. Demand-pages the destination range on the way
/// in so uncommitted pages are populated before the memcpy.
fn writeUser(proc: *Process, user_va: u64, data: []const u8) bool {
    if (user_va == 0) return false;
    if (!address.AddrSpacePartition.user.contains(user_va)) return false;
    const end = std.math.add(u64, user_va, data.len) catch return false;
    if (!address.AddrSpacePartition.user.contains(end -| 1)) return false;

    var remaining: usize = data.len;
    var src_off: usize = 0;
    var dst_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = dst_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(dst_va), true, false) catch return false;
        const page_paddr = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        @memcpy(dst[0..chunk], data[src_off..][0..chunk]);
        src_off += chunk;
        dst_va += chunk;
        remaining -= chunk;
    }
    return true;
}
