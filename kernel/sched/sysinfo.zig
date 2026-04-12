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
//! documented in systems.md §21 "System Info Internals".

const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const scheduler = zag.sched.scheduler;

const Process = zag.sched.process.Process;
const VAddr = zag.memory.address.VAddr;

// KEEP IN SYNC with kernel/arch/syscall.zig ──────────────────────────────
const E_OK: i64 = 0;
const E_BADADDR: i64 = -7;

// ── Observable types (spec §2.15) ───────────────────────────────────────

/// System-wide static and dynamic properties. Written to `info_ptr` by
/// every `sys_info` call (spec §2.15.1–§2.15.3).
pub const SysInfo = extern struct {
    core_count: u64,
    mem_total: u64,
    mem_free: u64,
};

/// Per-core dynamic properties, one entry per core indexed by core ID
/// (spec §2.15.4–§2.15.8). Field order matches the spec's prose:
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
    // `core_count * sizeof(CoreInfo)` bytes. Validate the full range up
    // front via a one-byte-span probe so a bad pointer is reported as
    // E_BADADDR before any accounting is reset.
    const total_bytes = std.math.mul(u64, core_count, @sizeOf(CoreInfo)) catch
        return E_BADADDR;
    if (!validateUserWritable(cores_ptr, total_bytes)) return E_BADADDR;

    // Info pointer also has to be writable (§4.55.3). Validate it here
    // after `cores_ptr` so neither side gets to touch state on a bad
    // address.
    if (!validateUserWritable(info_ptr, @sizeOf(SysInfo))) return E_BADADDR;

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
    while (i < core_count and i < MAX_CORES) : (i += 1) {
        const acct = scheduler.perCoreReadAndResetAccounting(i);
        entries[i] = .{
            .idle_ns = acct.idle_ns,
            .busy_ns = acct.busy_ns,
            .freq_hz = arch.getCoreFreq(i),
            .temp_mc = arch.getCoreTemp(i),
            .c_state = arch.getCoreState(i),
        };
    }

    if (!writeUser(proc, info_ptr, std.mem.asBytes(&info))) return E_BADADDR;

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
