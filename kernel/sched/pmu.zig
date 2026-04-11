//! Generic PMU syscall layer.
//!
//! Defines the observable PMU types (`PmuEvent`, `PmuCounterConfig`,
//! `PmuInfo`, `PmuSample`) and implements `sysPmuInfo`, `sysPmuStart`,
//! `sysPmuRead`, `sysPmuReset`, `sysPmuStop`. All hardware touching is
//! delegated to `arch.pmuXxx`; this file contains zero x86-specific state
//! or MSR references (see systems.md §20).
//!
//! Capability model (spec §2.14.1–§2.14.6):
//!   * `ProcessRights.pmu` on slot 0 of the calling process gates every
//!     PMU syscall that takes a thread handle.
//!   * `ThreadHandleRights.pmu` is additionally required on the thread
//!     entry for every such syscall.
//!   * `sysPmuInfo` skips both checks (spec §2.14.1 / §4.50.2).

const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const scheduler = zag.sched.scheduler;
const slab_allocator = zag.memory.slab_allocator;

const Process = zag.sched.process.Process;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

// KEEP IN SYNC with kernel/arch/syscall.zig ──────────────────────────────
// Duplicated here (rather than imported) so this file has no dependency
// on the arch-layer syscall dispatch module; if you add or renumber any
// error code in `kernel/arch/syscall.zig` mirror it here.
const E_OK: i64 = 0;
const E_INVAL: i64 = -1;
const E_PERM: i64 = -2;
const E_BADCAP: i64 = -3;
const E_NOMEM: i64 = -4;
const E_BADADDR: i64 = -7;
const E_BUSY: i64 = -11;

// ── Observable types (spec §2.14) ───────────────────────────────────────

/// Named hardware event types. The kernel maps each variant to the
/// appropriate architectural event on the host machine (x64:
/// CPUID.0AH-based architectural events from Intel SDM Vol 3 Table 18-2).
///
/// `supported_events` in `PmuInfo` is a bitmask with one bit per variant
/// here (bit 0 = `.cycles`, bit 1 = `.instructions`, etc.) indicating
/// which variants the host CPU actually implements.
pub const PmuEvent = enum(u8) {
    cycles = 0,
    instructions = 1,
    cache_references = 2,
    cache_misses = 3,
    branch_instructions = 4,
    branch_misses = 5,
    bus_cycles = 6,
    stalled_cycles_frontend = 7,
    stalled_cycles_backend = 8,
    _,
};

/// One counter configuration.
///
/// Userspace layout: `event` at offset 0, an 8-byte-aligned pad at offset
/// 1..8, then `has_threshold` + `overflow_threshold` forming the optional
/// threshold pair at offset 8..24. Encoding `?u64` directly as `extern
/// struct` is not FFI-safe across toolchains; we use the pair form so the
/// ABI layout is deterministic and the spec's "null = precise counting"
/// maps to `has_threshold == false`.
pub const PmuCounterConfig = extern struct {
    event: PmuEvent,
    _pad: [7]u8 = .{0} ** 7,
    has_threshold: bool,
    _pad2: [7]u8 = .{0} ** 7,
    overflow_threshold: u64,
};

/// Hardware PMU capability description returned by `pmu_info`.
pub const PmuInfo = extern struct {
    num_counters: u8,
    overflow_support: bool,
    _pad: [6]u8 = .{0} ** 6,
    supported_events: u64,
};

/// Compile-time ceiling on the number of hardware counter slots exposed
/// through `PmuSample`. Sized to fit Intel architectural PMU v4+ and AMD
/// PerfMonV2, both of which cap general-purpose counters at 8 per logical
/// core (Intel SDM Vol 3 §18.2.5 / AMD APM Vol 2 §13.2.1). Re-exported to
/// the dispatch layer as `arch.dispatch.pmu_max_counters`, and mirrored by
/// each arch's `PmuState` (see `arch/x64/pmu.zig:MAX_COUNTERS`).
/// Slots beyond `PmuInfo.num_counters` in a `PmuSample` are zero.
pub const MAX_COUNTERS: u8 = 8;

pub const PmuSample = extern struct {
    counters: [MAX_COUNTERS]u64 = .{0} ** MAX_COUNTERS,
    timestamp: u64 = 0,
};

// ── PmuStateAllocator (slab) ────────────────────────────────────────────

/// Lazily-allocated per-thread PMU state. Chunk size matches the other
/// per-thread slabs (64). `arch.PmuState` is the arch-dispatched type
/// (empty stub on aarch64, ~200 B on x64).
pub const PmuStateAllocator = slab_allocator.SlabAllocator(arch.PmuState, false, 0, 64, true);

pub var allocator: std.mem.Allocator = undefined;
var slab_instance: PmuStateAllocator = undefined;

pub fn initSlab(backing_allocator: std.mem.Allocator) !void {
    slab_instance = try PmuStateAllocator.init(backing_allocator);
    allocator = slab_instance.allocator();
}

// ── Syscall entry points ────────────────────────────────────────────────

/// §4.50 pmu_info(info_ptr). No rights checks (§4.50.2).
pub fn sysPmuInfo(proc: *Process, info_ptr: u64) i64 {
    const info = arch.pmuGetInfo();
    var buf: [@sizeOf(PmuInfo)]u8 = undefined;
    @memcpy(&buf, std.mem.asBytes(&info));
    if (!writeUser(proc, info_ptr, &buf)) return E_BADADDR;
    return E_OK;
}

/// §4.51 pmu_start(thread_handle, configs_ptr, count).
pub fn sysPmuStart(proc: *Process, thread_handle: u64, configs_ptr: u64, count: u64) i64 {
    const rights_err = checkRights(proc, thread_handle);
    if (rights_err) |e| return e;
    const target_thread = lookupThread(proc, thread_handle) orelse return E_BADCAP;

    var configs: [arch.pmu_max_counters]PmuCounterConfig = undefined;
    const slice = readConfigs(proc, configs_ptr, count, &configs) catch |err| return configErrToCode(err);

    const target_proc = target_thread.process;
    target_proc.lock.lock();
    defer target_proc.lock.unlock();

    // Self vs. remote programming. Writing MSRs on the caller's core only
    // makes sense if the caller *is* the target — otherwise we'd trash the
    // caller's own PMU state and do nothing to the target's actual core.
    // For a remote target we stamp `state` from the caller's core, so the
    // target must not be actively scheduled on another core at the same
    // time — otherwise `pmuConfigureState` here races `pmuSave`/`pmuRestore`
    // there. Require the target to be observable (.faulted or .suspended);
    // return E_BUSY otherwise (§4.51.11).
    const is_self = target_thread == scheduler.currentThread();
    if (!is_self) {
        switch (target_thread.state) {
            .faulted, .suspended => {},
            else => return E_BUSY,
        }
    }

    // Allocate PMU state lazily on first start (§2.14.8).
    if (target_thread.pmu_state == null) {
        const new_state = allocator.create(arch.PmuState) catch return E_NOMEM;
        new_state.* = .{};
        target_thread.pmu_state = new_state;
    }
    const state = target_thread.pmu_state.?;

    if (is_self) {
        arch.pmuStart(state, slice) catch return E_INVAL;
    } else {
        arch.pmuConfigureState(state, slice);
    }
    return E_OK;
}

/// §4.52 pmu_read(thread_handle, sample_ptr).
pub fn sysPmuRead(proc: *Process, thread_handle: u64, sample_ptr: u64) i64 {
    const rights_err = checkRights(proc, thread_handle);
    if (rights_err) |e| return e;
    const target_thread = lookupThread(proc, thread_handle) orelse return E_BADCAP;

    const target_proc = target_thread.process;
    target_proc.lock.lock();
    defer target_proc.lock.unlock();

    // §2.14.11 / §4.52.5: only .faulted or .suspended is legal.
    switch (target_thread.state) {
        .faulted, .suspended => {},
        else => return E_BUSY,
    }

    const state = target_thread.pmu_state orelse return E_INVAL; // §4.52.6

    var sample: PmuSample = .{};
    arch.pmuRead(state, &sample);
    sample.timestamp = arch.getMonotonicClock().now();

    var buf: [@sizeOf(PmuSample)]u8 = undefined;
    @memcpy(&buf, std.mem.asBytes(&sample));
    if (!writeUser(proc, sample_ptr, &buf)) return E_BADADDR;
    return E_OK;
}

/// §4.53 pmu_reset(thread_handle, configs_ptr, count).
pub fn sysPmuReset(proc: *Process, thread_handle: u64, configs_ptr: u64, count: u64) i64 {
    const rights_err = checkRights(proc, thread_handle);
    if (rights_err) |e| return e;
    const target_thread = lookupThread(proc, thread_handle) orelse return E_BADCAP;

    var configs: [arch.pmu_max_counters]PmuCounterConfig = undefined;
    const slice = readConfigs(proc, configs_ptr, count, &configs) catch |err| return configErrToCode(err);

    const target_proc = target_thread.process;
    target_proc.lock.lock();
    defer target_proc.lock.unlock();

    // §4.53.5: only .faulted is valid.
    if (target_thread.state != .faulted) return E_INVAL;

    const state = target_thread.pmu_state orelse return E_INVAL; // §4.53.6

    // Self vs. remote: a .faulted target can only be `currentThread()`
    // if the thread is handling its own fault (thread-level self-handler,
    // §2.12.7) — otherwise the faulted thread is sitting in its handler's
    // fault box and we're the profiler. Branch so the hardware-programming
    // path only runs when the target really is on this core.
    if (target_thread == scheduler.currentThread()) {
        arch.pmuReset(state, slice) catch return E_INVAL;
    } else {
        arch.pmuConfigureState(state, slice);
    }
    return E_OK;
}

/// §4.54 pmu_stop(thread_handle).
pub fn sysPmuStop(proc: *Process, thread_handle: u64) i64 {
    const rights_err = checkRights(proc, thread_handle);
    if (rights_err) |e| return e;
    const target_thread = lookupThread(proc, thread_handle) orelse return E_BADCAP;

    const target_proc = target_thread.process;
    target_proc.lock.lock();
    defer target_proc.lock.unlock();

    // Self vs. remote: only touch hardware on the caller's core if the
    // caller IS the target. Otherwise, the target isn't running here —
    // pmuStop would write MSRs on the wrong core. For a remote target we
    // take the pmuClearState path, which drops state without any MSR
    // writes; but if the target is still running on its own core it will
    // keep that core's IA32_PERFEVTSELx programmed with the old config
    // until the next context switch, and `pmuSave` on that core would
    // race our state mutation here. Require the target to be observable
    // (.faulted or .suspended); return E_BUSY otherwise (§4.54.7).
    const is_self = target_thread == scheduler.currentThread();
    if (!is_self) {
        switch (target_thread.state) {
            .faulted, .suspended => {},
            else => return E_BUSY,
        }
    }

    const state = target_thread.pmu_state orelse return E_INVAL; // §4.54.5

    if (is_self) {
        arch.pmuStop(state);
    } else {
        arch.pmuClearState(state);
    }
    target_thread.pmu_state = null;
    allocator.destroy(state);
    return E_OK;
}

// ── Internal helpers ────────────────────────────────────────────────────

/// Look up a thread handle and verify the entry is actually a thread.
fn lookupThread(proc: *Process, thread_handle: u64) ?*Thread {
    const entry = proc.getPermByHandle(thread_handle) orelse return null;
    if (entry.object != .thread) return null;
    return entry.object.thread;
}

/// Dual-gated rights check. Returns null on success, error code on failure.
/// Ordering: (a) look up the thread handle and type-check it first so an
/// invalid handle always surfaces as `E_BADCAP`, regardless of whether the
/// caller also lacks `ProcessRights.pmu`; (b) check `ProcessRights.pmu`
/// on slot 0; (c) check `ThreadHandleRights.pmu` on the thread entry.
/// (a) maps to §4.5{1,2,3,4}.4, (b) to §4.5{1,2,3,4}.2, (c) to §4.5{1,2,3,4}.3.
fn checkRights(proc: *Process, thread_handle: u64) ?i64 {
    const thread_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thread_entry.object != .thread) return E_BADCAP;

    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().pmu) return E_PERM;

    if (!thread_entry.threadHandleRights().pmu) return E_PERM;
    return null;
}

const ConfigReadError = error{
    BadAddress,
    Invalid,
};

/// Read and validate a `configs[count]` array from userspace.
///
/// On success the returned slice aliases into `out_buf` and is valid for
/// the remainder of the syscall. All validation described by spec
/// §4.51.5–§4.51.9 (count bounds, supported events, overflow support,
/// readable buffer) is applied here.
fn readConfigs(
    proc: *Process,
    configs_ptr: u64,
    count: u64,
    out_buf: []PmuCounterConfig,
) ConfigReadError![]const PmuCounterConfig {
    if (count == 0) return ConfigReadError.Invalid; // §4.51.5

    // §4.51.9 takes precedence over §4.51.6: a caller that passes an
    // unmapped `configs_ptr` together with an absurd `count` (e.g. 10000)
    // must observe E_BADADDR, not E_INVAL. Validate a readable slice
    // covering *the portion of `count` we can actually read*
    // (`min(count, out_buf.len)`) first so a bad pointer always surfaces
    // as E_BADADDR; then apply the `count > out_buf.len` and
    // `count > num_counters` bounds, which produce E_INVAL.
    const read_count = @min(count, out_buf.len);
    const read_bytes = std.math.mul(u64, read_count, @sizeOf(PmuCounterConfig)) catch
        return ConfigReadError.Invalid;

    const raw: []u8 = std.mem.sliceAsBytes(out_buf[0..@intCast(read_count)]);
    if (!readUser(proc, configs_ptr, raw[0..@intCast(read_bytes)])) return ConfigReadError.BadAddress;

    // Cap `count` against the kernel buffer. Anything over `MAX_COUNTERS`
    // also exceeds `PmuInfo.num_counters` by construction (§2.14 / §5:
    // `num_counters <= MAX_COUNTERS`), so §4.51.6 E_INVAL applies.
    if (count > out_buf.len) return ConfigReadError.Invalid; // §4.51.6

    const info = arch.pmuGetInfo();
    if (count > info.num_counters) return ConfigReadError.Invalid; // §4.51.6

    // §4.51.7 / §4.51.8: per-entry validation.
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const cfg = out_buf[i];
        // `PmuEvent` is an open `enum(u8)`, so userspace can pass any value
        // 0..255. `supported_events` is a u64 bitmask (bit i = variant i), so
        // any event value ≥ 64 is definitionally unsupported — reject up front
        // rather than `@intCast`-panicking on a value that doesn't fit u6.
        const ev_raw: u8 = @intFromEnum(cfg.event);
        if (ev_raw >= 64) return ConfigReadError.Invalid; // §4.51.7
        const ev_bit_idx: u6 = @intCast(ev_raw);
        const event_bit = @as(u64, 1) << ev_bit_idx;
        if ((info.supported_events & event_bit) == 0) return ConfigReadError.Invalid;
        if (cfg.has_threshold and !info.overflow_support) return ConfigReadError.Invalid;
    }
    return out_buf[0..@intCast(count)];
}

fn configErrToCode(err: ConfigReadError) i64 {
    return switch (err) {
        ConfigReadError.BadAddress => E_BADADDR,
        ConfigReadError.Invalid => E_INVAL,
    };
}

/// Read `buf.len` bytes from the caller's address space into `buf`, via
/// physmap, handling cross-page boundaries. Demand-pages the source range
/// on the way in so uncommitted pages are populated before the memcpy.
fn readUser(proc: *Process, user_va: u64, buf: []u8) bool {
    if (user_va == 0) return false;
    if (!address.AddrSpacePartition.user.contains(user_va)) return false;
    const end = std.math.add(u64, user_va, buf.len) catch return false;
    if (!address.AddrSpacePartition.user.contains(end -| 1)) return false;

    var remaining: usize = buf.len;
    var dst_off: usize = 0;
    var src_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = src_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(src_va), false, false) catch return false;
        const page_paddr = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        @memcpy(buf[dst_off..][0..chunk], src[0..chunk]);
        dst_off += chunk;
        src_va += chunk;
        remaining -= chunk;
    }
    return true;
}

/// Write `data` into the caller's address space via physmap.
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
