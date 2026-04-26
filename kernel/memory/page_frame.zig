//! Page Frame — reference to a contiguous physical memory region.
//! Installing it into virtual address ranges bound to multiple
//! capability domains creates shared memory. See spec §[page_frame].
//!
//! Refcount lifetime — total handles across all capability domains
//! plus VAR installations keep the underlying physical pages alive.
//! When the last handle drops the physical memory returns to the free
//! pool.

const std = @import("std");
const zag = @import("zag");

const capability = zag.caps.capability;
const capability_domain = zag.capdom.capability_domain;
const errors = zag.syscall.errors;
const pmm = zag.memory.pmm;
const var_range = zag.capdom.var_range;

const CapabilityDomain = capability_domain.CapabilityDomain;
const CapabilityType = capability.CapabilityType;
const ErasedSlabRef = capability.ErasedSlabRef;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;

/// Page size encoding (immutable per page frame). Same enum used by
/// VAR — re-exported for convenience.
pub const PageSize = var_range.PageSize;

/// Cap bits in `Capability.word0[48..63]` for page_frame handles.
/// Spec §[page_frame] cap layout.
pub const PageFrameCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    r: bool = false,
    w: bool = false,
    x: bool = false,
    max_sz: u2 = 0,
    restart_policy: u1 = 0,
    _reserved: u8 = 0,
};

pub const PageFrame = struct {
    /// Slab generation lock + per-instance mutex.
    _gen_lock: GenLock = .{},

    /// Total user-visible handles across all capability domains. Plain
    /// u32 mutated under `_gen_lock`; the decrementer that brings
    /// this to 0 owns teardown (returns physical pages to PMM).
    refcount: u32 = 0,

    /// Total active installations across all VARs and IOMMU domains.
    /// Mirrors user-visible field1 bits 0-31 (`mapcnt`). Mutated by
    /// `map_pf` / `unmap` and IOMMU bind/unbind paths under
    /// `_gen_lock`. snapshot binding stability check requires this
    /// to be exactly 1.
    mapcnt: u32 = 0,

    /// Physical base address of the backing memory. Set at create;
    /// immutable.
    phys_base: PAddr,

    /// Number of pages in `sz` units. Mirrors field0 bits 0-31. Set
    /// at create; immutable.
    page_count: u32,

    /// Page size (immutable). Mirrors field0 bits 32-33.
    sz: PageSize,
};

pub const Allocator = SecureSlab(PageFrame, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

// ── External API ─────────────────────────────────────────────────────

/// `create_page_frame` syscall handler. Spec §[page_frame].
pub fn createPageFrame(caller: *anyopaque, caps: u64, props: u64, pages: u64) i64 {
    // Reserved-bit validation (test 08): caps' upper 48 bits must be
    // zero; props' upper 62 bits must be zero. Fail fast before any
    // expensive lookup or allocation.
    if (caps >> 16 != 0) return errors.E_INVAL;
    if (props >> 2 != 0) return errors.E_INVAL;

    if (pages == 0) return errors.E_INVAL;

    const caps_bits: PageFrameCaps = @bitCast(@as(u16, @truncate(caps)));
    const sz_raw: u2 = @truncate(props);

    // Reserved page-size encodings (test 05, test 06).
    if (caps_bits.max_sz == @intFromEnum(PageSize._reserved)) return errors.E_INVAL;
    if (sz_raw == @intFromEnum(PageSize._reserved)) return errors.E_INVAL;

    // sz must not exceed max_sz (test 07).
    if (sz_raw > caps_bits.max_sz) return errors.E_INVAL;

    const sz: PageSize = @enumFromInt(sz_raw);

    // u32 page_count fits the field0 layout.
    if (pages > std.math.maxInt(u32)) return errors.E_INVAL;
    const page_count: u32 = @intCast(pages);

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));

    if (selfHandleLacksCrpf(ec)) return errors.E_PERM;
    if (!rwxIsSubsetOfCeiling(ec, caps_bits)) return errors.E_PERM;
    if (!maxSzWithinCeiling(ec, caps_bits)) return errors.E_PERM;

    const pf = allocPageFrame(sz, page_count) catch return errors.E_NOMEM;

    // Mint the user-visible handle into the caller's table. The kernel
    // table entry holds the `SlabRef(PageFrame)` (gen-validated); the
    // user table mirrors caps + field0/field1 snapshot.
    const cd = callerDomain(ec);
    const erased: ErasedSlabRef = .{
        .ptr = @ptrCast(pf),
        .gen = @intCast(pf._gen_lock.currentGen()),
    };
    const field0: u64 = packField0(page_count, sz);
    const field1: u64 = 0;
    const slot = capability_domain.mintHandle(
        cd,
        erased,
        CapabilityType.page_frame,
        @as(u16, @bitCast(caps_bits)),
        field0,
        field1,
    ) catch {
        // Handle table full: drop the lone refcount we minted; mapcnt
        // was 0, so this triggers full teardown back to PMM.
        decHandleRef(pf);
        return errors.E_FULL;
    };

    return @as(i64, slot);
}

// ── Internal API ─────────────────────────────────────────────────────

/// Allocate a PageFrame slot + `page_count` pages of `sz` from PMM,
/// refcount=1, mapcnt=0. Spec §[page_frame] create.
fn allocPageFrame(sz: PageSize, page_count: u32) !*PageFrame {
    const page_bytes: u64 = pageSizeBytes(sz);
    const total_bytes: u64 = page_bytes * @as(u64, page_count);

    const pmm_mgr = &(pmm.global_pmm orelse return error.OutOfMemory);
    const block = pmm_mgr.allocBlock(total_bytes) orelse return error.OutOfMemory;
    errdefer pmm_mgr.freeBlock(block[0..total_bytes]);

    const ref = slab_instance.create() catch return error.OutOfMemory;

    // SecureSlab.create returns a zeroed slot with gen flipped to live.
    // Caller is the sole observer until the handle is published, so
    // direct field writes are safe (no lock/unlock bracketing needed).
    const pf = ref.ptr;
    pf.refcount = 1;
    pf.mapcnt = 0;
    pf.phys_base = PAddr.fromInt(@intFromPtr(block));
    pf.page_count = page_count;
    pf.sz = sz;

    return pf;
}

/// Final teardown — caller has observed refcount==0 AND mapcnt==0 under
/// `_gen_lock`. Returns physical pages to PMM and frees the slab slot.
fn destroyPageFrame(pf: *PageFrame) void {
    // Snapshot what we need before the slab destroy invalidates `pf`.
    const phys = pf.phys_base.addr;
    const total_bytes = pageSizeBytes(pf.sz) * @as(u64, pf.page_count);
    const expected_gen: u63 = @intCast(pf._gen_lock.currentGen());

    // Caller holds the gen-lock at expected_gen (per the inc/dec
    // contract that observed both counters at zero); destroyLocked
    // clears the slot and bumps the gen as part of releasing the lock.
    slab_instance.destroyLocked(pf, expected_gen);

    // PMM freeBlock zero-fills before returning pages to the buddy, so
    // the next allocator sees a clean region.
    if (pmm.global_pmm) |*pmm_mgr| {
        const ptr: [*]u8 = @ptrFromInt(phys);
        pmm_mgr.freeBlock(ptr[0..total_bytes]);
    }
}

/// Handle copy/transfer: increment refcount under `_gen_lock`.
fn incHandleRef(pf: *PageFrame) void {
    pf._gen_lock.lock(@src());
    defer pf._gen_lock.unlock();
    // Saturate to keep refcount overflow from aliasing a destroy
    // decision against a still-live holder.
    if (pf.refcount != std.math.maxInt(u32)) pf.refcount += 1;
}

/// Handle delete: decrement refcount under `_gen_lock`; if both
/// refcount and mapcnt are zero, calls `destroyPageFrame`.
fn decHandleRef(pf: *PageFrame) void {
    pf._gen_lock.lock(@src());
    if (pf.refcount > 0) pf.refcount -= 1;
    const reached_zero = pf.refcount == 0 and pf.mapcnt == 0;
    if (!reached_zero) {
        pf._gen_lock.unlock();
        return;
    }
    // Lock stays held — destroyPageFrame routes through
    // SecureSlab.destroyLocked which expects the gen-lock held and
    // releases it as part of the gen bump.
    destroyPageFrame(pf);
}

/// Public release-handle entry point invoked from the cross-cutting
/// `caps.capability.delete` path. Wraps `decHandleRef` for callers
/// that don't have access to the module-private helper.
pub fn releaseHandle(pf: *PageFrame) void {
    decHandleRef(pf);
}

/// VAR install: increment mapcnt under `_gen_lock`, saturating at
/// `u32::MAX`. Spec §[page_frame] field1.
fn incMapCnt(pf: *PageFrame) void {
    pf._gen_lock.lock(@src());
    defer pf._gen_lock.unlock();
    if (pf.mapcnt != std.math.maxInt(u32)) pf.mapcnt += 1;
}

/// VAR unmap: decrement mapcnt under `_gen_lock`; if both refcount and
/// mapcnt are zero, calls `destroyPageFrame`.
fn decMapCnt(pf: *PageFrame) void {
    pf._gen_lock.lock(@src());
    if (pf.mapcnt > 0) pf.mapcnt -= 1;
    const reached_zero = pf.refcount == 0 and pf.mapcnt == 0;
    if (!reached_zero) {
        pf._gen_lock.unlock();
        return;
    }
    destroyPageFrame(pf);
}

/// Snapshot stability predicate (called at restart for snapshot-bound
/// VARs). Returns true iff `mapcnt == 1` AND no live writable
/// installation. Spec §[var] snapshot.
fn snapshotStable(pf: *PageFrame, var_eff_w: bool) bool {
    pf._gen_lock.lock(@src());
    defer pf._gen_lock.unlock();
    // mapcnt > 1 means another VAR / IOMMU domain holds an active
    // installation; snapshot binding cannot prove the source page is
    // immutable. mapcnt == 0 is also unstable (the source isn't
    // installed anywhere right now).
    if (pf.mapcnt != 1) return false;
    // `var_eff_w` is the source VAR's effective write bit; if it can
    // write to this page, the snapshot would race against the writer.
    if (var_eff_w) return false;
    return true;
}

// ── Helpers ──────────────────────────────────────────────────────────

inline fn pageSizeBytes(sz: PageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x200000,
        .sz_1g => 0x40000000,
        ._reserved => unreachable,
    };
}

inline fn packField0(page_count: u32, sz: PageSize) u64 {
    return @as(u64, page_count) | (@as(u64, @intFromEnum(sz)) << 32);
}

/// Resolve the caller's owning capability domain. The syscall ABI
/// dispatches via `*anyopaque`; the concrete type is `*ExecutionContext`
/// whose `domain` SlabRef names the owner.
fn callerDomain(ec: *ExecutionContext) *CapabilityDomain {
    return ec.domain.ptr;
}

/// Self-handle `crpf` predicate (test 01). The capability-domain
/// helpers needed to read the self-handle's cap bits aren't present
/// yet; this returns `false` (cap present) until they land so the
/// rest of the path can be exercised.
fn selfHandleLacksCrpf(ec: *ExecutionContext) bool {
    _ = ec;
    return false;
}

/// `caps.r/w/x` ⊆ `pf_ceiling.max_rwx` predicate (test 02). See
/// `selfHandleLacksCrpf` re: deferred ceiling lookup.
fn rwxIsSubsetOfCeiling(ec: *ExecutionContext, caps_bits: PageFrameCaps) bool {
    _ = ec;
    _ = caps_bits;
    return true;
}

/// `caps.max_sz` ≤ `pf_ceiling.max_sz` predicate (test 03). See
/// `selfHandleLacksCrpf` re: deferred ceiling lookup.
fn maxSzWithinCeiling(ec: *ExecutionContext, caps_bits: PageFrameCaps) bool {
    _ = ec;
    _ = caps_bits;
    return true;
}
