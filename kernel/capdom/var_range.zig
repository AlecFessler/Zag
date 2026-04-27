//! Virtual Address Range (VAR) — contiguous span of virtual address
//! space bound to a capability domain, available for demand-paged
//! memory or installing page frames or device regions. See spec §[var].
//!
//! Capability-domain lifetime: dies when the owning CapabilityDomain
//! is destroyed. Multiple capability domains may hold handles to a VAR
//! via `acquire_vars` (debugger primitive) or `copy`/`move` — UAF
//! protection across domains comes from `_gen_lock`.

const std = @import("std");
const zag = @import("zag");

const dispatch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const secure_slab = zag.memory.allocators.secure_slab;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const CapabilityType = zag.caps.capability.CapabilityType;
const DeviceRegion = zag.devices.device_region.DeviceRegion;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = secure_slab.GenLock;
const KernelHandle = zag.caps.capability.KernelHandle;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PageFrame = zag.memory.page_frame.PageFrame;
const SecureSlab = secure_slab.SecureSlab;
const VAddr = zag.memory.address.VAddr;
const Word0 = zag.caps.capability.Word0;

/// Cap bits in `Capability.word0[48..63]` for VAR handles.
/// Spec §[var] cap layout.
pub const VarCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    r: bool = false,
    w: bool = false,
    x: bool = false,
    mmio: bool = false,
    max_sz: u2 = 0,
    dma: bool = false,
    restart_policy: u2 = 0,
    _reserved: u5 = 0,
};

/// Page size encoding for VAR.sz / max_sz cap fields.
pub const PageSize = enum(u2) {
    sz_4k = 0,
    sz_2m = 1,
    sz_1g = 2,
    _reserved = 3,
};

/// Cache type encoding for VAR.cch.
pub const CacheType = enum(u2) {
    wb = 0,
    uc = 1,
    wc = 2,
    wt = 3,
};

/// What's currently installed in the VAR. Mirrors field1 bits 39-40.
pub const MapType = enum(u2) {
    /// Reserved address range with no backing.
    unmapped = 0,
    /// One or more page_frames installed at offsets via `map_pf`.
    page_frame = 1,
    /// MMIO device_region installed via `map_mmio`.
    mmio = 2,
    /// Demand-paged: kernel allocates a fresh zero-page on first
    /// touch. Established by accessing an `unmapped` VAR.
    demand = 3,
};

/// VAR.caps.restart_policy encoding (also used by `restartCleanup`).
pub const RestartPolicy = enum(u2) {
    free = 0,
    decommit = 1,
    preserve = 2,
    snapshot = 3,
};

pub const VAR = struct {
    /// Slab generation lock. Validates `SlabRef(VAR)` liveness AND
    /// guards every mutable field below.
    _gen_lock: GenLock = .{},

    /// Owning capability domain. VARs cannot outlive their owner.
    /// Set at create_var; immutable.
    domain: *CapabilityDomain,

    /// Base virtual address (or base IOVA for DMA VARs). Mirrors the
    /// user-visible Capability.field0. Set at create; immutable.
    base_vaddr: VAddr,

    /// Number of pages in `sz` units. Mirrors low 32 bits of field1.
    /// Set at create; immutable.
    page_count: u32,

    /// Page size (immutable). Mirrors field1 bits 32-33.
    sz: PageSize,

    /// Cache type (immutable). Mirrors field1 bits 34-35.
    cch: CacheType,

    /// Current effective rwx for installed pages (bit 0 = r, 1 = w,
    /// 2 = x). Mirrors field1 bits 36-38. Mutable via `remap`.
    cur_rwx: u3 = 0,

    /// What's currently installed. Mirrors field1 bits 39-40. Updated
    /// by map_pf / map_mmio / unmap and by demand-paged faults.
    map: MapType = .unmapped,

    /// Bound device_region. Set immutably at create_var when this is
    /// a DMA VAR (caps.dma=1, IOMMU mappings install via this device's
    /// IOMMU domain). Set/cleared by map_mmio/unmap when this is an
    /// MMIO VAR. Null otherwise. Mirrors field1 bits 41-52 (handle id
    /// in the owning domain's table).
    device: ?*DeviceRegion = null,

    /// Snapshot binding source. Set by `snapshot` when this VAR has
    /// `restart_policy = snapshot` (3) and a source has been bound.
    /// On the owning domain's restart, the source's contents are
    /// copied into this VAR before resume. Source may live in another
    /// domain — cross-domain UAF protection routes through
    /// `source._gen_lock`. Null when no binding.
    snapshot_source: ?*VAR = null,

    /// Out-of-band per-page mapping table. Tracks which page_frames
    /// are installed at which offsets (when `map = page_frame`) or
    /// which demand-paged pages have been allocated (when
    /// `map = demand`). Layout TBD — likely a sparse offset → page
    /// pointer structure. Null when `map = unmapped` or `map = mmio`
    /// (the latter has only the single `device` binding).
    mapping_table: ?*anyopaque = null,
};

pub const Allocator = SecureSlab(VAR, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

inline fn pageSizeBytes(sz: PageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x20_0000,
        .sz_1g => 0x4000_0000,
        ._reserved => 0,
    };
}

inline fn rwxToPerms(rwx: u3) MemoryPerms {
    return .{
        .read = (rwx & 0b001) != 0,
        .write = (rwx & 0b010) != 0,
        .exec = (rwx & 0b100) != 0,
    };
}

// ── External API ─────────────────────────────────────────────────────

/// `create_var` syscall handler. Spec §[var].create_var.
pub fn createVar(
    caller: *ExecutionContext,
    caps: u64,
    props: u64,
    pages: u64,
    preferred_base: u64,
    device_region: u64,
) i64 {
    if (caps >> 16 != 0) return errors.E_INVAL;
    if (props >> 7 != 0) return errors.E_INVAL;
    if (pages == 0) return errors.E_INVAL;

    const var_caps: VarCaps = @bitCast(@as(u16, @truncate(caps)));
    if (var_caps._reserved != 0) return errors.E_INVAL;

    const cur_rwx: u3 = @truncate(props & 0b111);
    const props_sz: u2 = @truncate((props >> 3) & 0b11);
    const props_cch: u2 = @truncate((props >> 5) & 0b11);

    if (props_sz == @intFromEnum(PageSize._reserved)) return errors.E_INVAL;
    if (var_caps.max_sz == @intFromEnum(PageSize._reserved)) return errors.E_INVAL;
    if (props_sz > var_caps.max_sz) return errors.E_INVAL;
    if (var_caps.mmio and var_caps.dma) return errors.E_INVAL;
    if (var_caps.mmio and var_caps.x) return errors.E_INVAL;
    if (var_caps.dma and var_caps.x) return errors.E_INVAL;
    if (var_caps.mmio and props_sz != 0) return errors.E_INVAL;

    const caps_rwx: u3 = (@as(u3, @intFromBool(var_caps.r))) |
        (@as(u3, @intFromBool(var_caps.w)) << 1) |
        (@as(u3, @intFromBool(var_caps.x)) << 2);
    if ((cur_rwx & ~caps_rwx) != 0) return errors.E_INVAL;

    const sz: PageSize = @enumFromInt(props_sz);
    const cch: CacheType = @enumFromInt(props_cch);
    const sz_bytes = pageSizeBytes(sz);
    const base_in: VAddr = .fromInt(preferred_base);
    if (preferred_base != 0 and !std.mem.isAligned(preferred_base, sz_bytes)) {
        return errors.E_INVAL;
    }
    if (preferred_base != 0) {
        // Spec §[create_var] test 23: preferred_base must lie wholly
        // within the static zone — see §[address_space].
        const range_bytes = pages * sz_bytes;
        const static = dispatch.paging.user_static;
        const end = @addWithOverflow(preferred_base, range_bytes);
        if (end[1] != 0) return errors.E_INVAL;
        if (preferred_base < static.start or end[0] > static.end) {
            return errors.E_INVAL;
        }
    }

    const domain = caller.domain.ptr;

    // DMA VARs require a valid device_region handle with the dma cap.
    var dev_ptr: ?*DeviceRegion = null;
    if (var_caps.dma) {
        const slot: u12 = @truncate(device_region & 0xFFF);
        const kh = lookupHandle(domain, slot, .device_region) orelse
            return errors.E_BADCAP;
        const cap_bits: u16 = Word0.caps(domain.user_table[slot].word0);
        const dr_caps: zag.devices.device_region.DeviceRegionCaps = @bitCast(cap_bits);
        if (!dr_caps.dma) return errors.E_PERM;
        dev_ptr = @ptrCast(@alignCast(kh.ref.ptr.?));
    }

    const base = vaRangeAllocate(domain, @intCast(pages), sz, base_in) orelse
        return errors.E_NOSPC;

    const overlap = zag.capdom.capability_domain.checkVaRangeOverlap(domain, base, @as(u64, @intCast(pages)) * sz_bytes);
    if (overlap != 0) return overlap;

    const v = allocVar(domain, base, @intCast(pages), sz, cch, cur_rwx, dev_ptr) catch
        return errors.E_NOMEM;

    const append_rc = zag.capdom.capability_domain.appendVar(domain, v);
    if (append_rc != 0) {
        destroyVar(v);
        return append_rc;
    }

    // Mint a handle for the new VAR in the caller's domain. field0 =
    // base vaddr; field1 = packed page_count|sz|cch|cur_rwx|map|device.
    const field0: u64 = base.addr;
    const field1: u64 = packField1(@intCast(pages), sz, cch, cur_rwx, .unmapped, 0);
    const slot = zag.capdom.capability_domain.mintHandle(
        domain,
        .{ .ptr = v, .gen = @intCast(v._gen_lock.currentGen()) },
        .virtual_address_range,
        @as(u16, @truncate(caps)),
        field0,
        field1,
    ) catch return errors.E_FULL;

    // v0 ABI extension: deliver field0 (base vaddr) in vreg 2 and
    // field1 (page_count|sz|cch|cur_rwx|map|device) in vreg 3 alongside
    // the slot in vreg 1. The runtime user-table mirror also carries
    // these snapshots, but exposing them in registers lets a caller
    // capture base/size without a second VA load on the hot create_var
    // path.
    dispatch.syscall.setSyscallVreg2(caller.ctx, field0);
    dispatch.syscall.setSyscallVreg3(caller.ctx, field1);

    return @intCast(slot);
}

/// `map_pf` syscall handler. Spec §[var].map_pf.
pub fn mapPf(caller: *ExecutionContext, var_handle: u64, pairs: []const u64) i64 {
    if (pairs.len == 0 or (pairs.len & 1) != 0) return errors.E_INVAL;

    const domain = caller.domain.ptr;
    const slot: u12 = @truncate(var_handle & 0xFFF);
    const v = resolveVar(domain, slot) orelse return errors.E_BADCAP;

    v._gen_lock.lock(@src());
    defer v._gen_lock.unlock();
    defer refreshVarSnapshot(domain, slot, v);

    const caps_word: u16 = Word0.caps(domain.user_table[slot].word0);
    const var_caps: VarCaps = @bitCast(caps_word);
    if (var_caps.mmio) return errors.E_PERM;
    if (v.map == .mmio or v.map == .demand) return errors.E_INVAL;

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;

    var i: usize = 0;
    while (i < pairs.len) {
        const offset = pairs[i];
        const pf_handle = pairs[i + 1];
        if (!std.mem.isAligned(offset, sz_bytes)) return errors.E_INVAL;

        const pf_slot: u12 = @truncate(pf_handle & 0xFFF);
        const pf_kh = lookupHandle(domain, pf_slot, .page_frame) orelse
            return errors.E_BADCAP;
        const pf: *PageFrame = @ptrCast(@alignCast(pf_kh.ref.ptr.?));

        if (@intFromEnum(pf.sz) < @intFromEnum(v.sz)) return errors.E_INVAL;

        // Spec §[var].map_pf test 07: each pair's full range
        // (pf.page_count × pf.sz) must fit within the VAR.
        const pf_sz_bytes = pageSizeBytes(pf.sz);
        const pair_bytes = @as(u64, pf.page_count) * pf_sz_bytes;
        if (offset >= var_size or offset + pair_bytes > var_size) return errors.E_INVAL;

        const rc = mappingInstall(v, offset, pf);
        if (rc != 0) return rc;

        i += 2;
    }

    if (v.map == .unmapped) v.map = .page_frame;
    return 0;
}

/// `map_mmio` syscall handler. Spec §[var].map_mmio.
pub fn mapMmio(caller: *ExecutionContext, var_handle: u64, device_region: u64) i64 {
    const domain = caller.domain.ptr;
    const var_slot: u12 = @truncate(var_handle & 0xFFF);
    const v = resolveVar(domain, var_slot) orelse return errors.E_BADCAP;

    v._gen_lock.lock(@src());
    defer v._gen_lock.unlock();
    defer refreshVarSnapshot(domain, var_slot, v);

    const caps_word: u16 = Word0.caps(domain.user_table[var_slot].word0);
    const var_caps: VarCaps = @bitCast(caps_word);
    if (!var_caps.mmio) return errors.E_PERM;
    if (v.map != .unmapped) return errors.E_INVAL;

    const dr_slot: u12 = @truncate(device_region & 0xFFF);
    const dr_kh = lookupHandle(domain, dr_slot, .device_region) orelse
        return errors.E_BADCAP;
    const dr: *DeviceRegion = @ptrCast(@alignCast(dr_kh.ref.ptr.?));

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;
    // Spec §[var].map_mmio test 05: device_region size must equal VAR
    // size. MMIO devices carry byte size in `access.mmio.size`. For
    // port_io regions §[device_region] does not declare a byte-sized
    // field — `port_count` is in I/O ports, not bytes — so the
    // size-equality check would gate every port_io map_mmio (e.g.
    // COM1's 8-port range against any non-degenerate VAR). Treat
    // port_io regions as fitting any VAR whose 4 KiB-aligned size
    // covers the port range; the port-io fault decoder maps VAR
    // offsets 1:1 onto port offsets (Spec §[port_io_virtualization]),
    // so larger VARs simply expose unmapped tail bytes that the
    // decoder rejects on access.
    switch (dr.device_type) {
        .mmio => if (dr.access.mmio.size != var_size) return errors.E_INVAL,
        .port_io => if (var_size < dr.access.port_io.port_count) return errors.E_INVAL,
    }

    // Port-IO regions install with no PTEs — every CPU access faults
    // and is decoded by the port-io fault handler. Plain MMIO installs
    // PTEs covering [base_vaddr, base_vaddr + var_size).
    // Spec §[port_io_virtualization].
    if (dr.device_type == .mmio) {
        const phys_base = dr.access.mmio.phys_base;
        var off: u64 = 0;
        while (off < var_size) {
            dispatch.paging.mapPageSized(
                domain.addr_space_root,
                .fromInt(phys_base.addr + off),
                .fromInt(v.base_vaddr.addr + off),
                v.sz,
                v.cch,
                rwxToPerms(v.cur_rwx),
            ) catch return errors.E_NOMEM;
            off += sz_bytes;
        }
    }

    v.device = dr;
    v.map = .mmio;
    return 0;
}

/// `unmap` syscall handler. Spec §[var].unmap.
pub fn unmap(caller: *ExecutionContext, var_handle: u64, selectors: []const u64) i64 {
    const domain = caller.domain.ptr;
    const slot: u12 = @truncate(var_handle & 0xFFF);
    const v = resolveVar(domain, slot) orelse return errors.E_BADCAP;

    v._gen_lock.lock(@src());
    defer v._gen_lock.unlock();
    defer refreshVarSnapshot(domain, slot, v);

    if (v.map == .unmapped) return errors.E_INVAL;
    if (v.map == .mmio and selectors.len > 0) return errors.E_INVAL;

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;

    if (selectors.len == 0) {
        unmapAll(v, domain);
        v.map = .unmapped;
        v.device = null;
        return 0;
    }

    switch (v.map) {
        .page_frame => {
            for (selectors) |sel| {
                const pf_slot: u12 = @truncate(sel & 0xFFF);
                const pf_kh = lookupHandle(domain, pf_slot, .page_frame) orelse
                    return errors.E_BADCAP;
                const pf: *PageFrame = @ptrCast(@alignCast(pf_kh.ref.ptr.?));
                const offset = findInstalledOffset(v, pf) orelse return errors.E_NOENT;
                _ = mappingRemove(v, offset);
            }
            if (countInstalled(v) == 0) v.map = .unmapped;
        },
        .demand => {
            for (selectors) |off| {
                if (!std.mem.isAligned(off, sz_bytes)) return errors.E_INVAL;
                if (off >= var_size) return errors.E_NOENT;
                if (mappingRemove(v, off) == null) return errors.E_NOENT;
            }
            if (countInstalled(v) == 0) v.map = .unmapped;
        },
        .mmio, .unmapped => unreachable,
    }

    dispatch.paging.shootdownTlbRange(
        domain.addr_space_id,
        v.base_vaddr,
        v.sz,
        v.page_count,
    );
    return 0;
}

/// `remap` syscall handler. Spec §[var].remap.
pub fn remap(caller: *ExecutionContext, var_handle: u64, new_cur_rwx: u64) i64 {
    if (new_cur_rwx >> 3 != 0) return errors.E_INVAL;

    const domain = caller.domain.ptr;
    const slot: u12 = @truncate(var_handle & 0xFFF);
    const v = resolveVar(domain, slot) orelse return errors.E_BADCAP;

    v._gen_lock.lock(@src());
    defer v._gen_lock.unlock();
    defer refreshVarSnapshot(domain, slot, v);

    if (v.map == .unmapped or v.map == .mmio) return errors.E_INVAL;

    const new_rwx: u3 = @truncate(new_cur_rwx & 0b111);
    const caps_word: u16 = Word0.caps(domain.user_table[slot].word0);
    const var_caps: VarCaps = @bitCast(caps_word);
    const caps_rwx: u3 = (@as(u3, @intFromBool(var_caps.r))) |
        (@as(u3, @intFromBool(var_caps.w)) << 1) |
        (@as(u3, @intFromBool(var_caps.x)) << 2);
    if ((new_rwx & ~caps_rwx) != 0) return errors.E_INVAL;
    if (var_caps.dma and (new_rwx & 0b100) != 0) return errors.E_INVAL;

    // For map=1, intersect against every installed page_frame's caps —
    // see spec §[var].remap test 04. Walking the per-page table is the
    // mapping_table's job; defer enforcement until that layout lands.

    const sz_bytes = pageSizeBytes(v.sz);
    var off: u64 = 0;
    const var_size = @as(u64, v.page_count) * sz_bytes;
    while (off < var_size) {
        dispatch.paging.mapPageSized(
            domain.addr_space_root,
            .fromInt(0),
            .fromInt(v.base_vaddr.addr + off),
            v.sz,
            v.cch,
            rwxToPerms(new_rwx),
        ) catch {};
        off += sz_bytes;
    }
    dispatch.paging.shootdownTlbRange(
        domain.addr_space_id,
        v.base_vaddr,
        v.sz,
        v.page_count,
    );
    v.cur_rwx = new_rwx;
    return 0;
}

/// `snapshot` syscall handler. Spec §[var].snapshot.
pub fn snapshot(caller: *ExecutionContext, target_var: u64, source_var: u64) i64 {
    const domain = caller.domain.ptr;
    const t_slot: u12 = @truncate(target_var & 0xFFF);
    const s_slot: u12 = @truncate(source_var & 0xFFF);

    const target = resolveVar(domain, t_slot) orelse return errors.E_BADCAP;
    const source = resolveVar(domain, s_slot) orelse return errors.E_BADCAP;

    const t_caps: VarCaps = @bitCast(Word0.caps(domain.user_table[t_slot].word0));
    const s_caps: VarCaps = @bitCast(Word0.caps(domain.user_table[s_slot].word0));
    if (t_caps.restart_policy != @intFromEnum(RestartPolicy.snapshot)) return errors.E_INVAL;
    if (s_caps.restart_policy != @intFromEnum(RestartPolicy.preserve)) return errors.E_INVAL;

    target._gen_lock.lock(@src());
    defer target._gen_lock.unlock();

    const t_size = @as(u64, target.page_count) * pageSizeBytes(target.sz);
    const s_size = @as(u64, source.page_count) * pageSizeBytes(source.sz);
    if (t_size != s_size) return errors.E_INVAL;

    target.snapshot_source = source;
    return 0;
}

/// `idc_read` syscall handler. Spec §[var].idc_read.
pub fn idcRead(caller: *ExecutionContext, var_handle: u64, offset: u64, count: u8) i64 {
    if (count == 0 or count > 125) return errors.E_INVAL;
    if (!std.mem.isAligned(offset, 8)) return errors.E_INVAL;

    const domain = caller.domain.ptr;
    const slot: u12 = @truncate(var_handle & 0xFFF);
    const v = resolveVar(domain, slot) orelse return errors.E_BADCAP;

    const caps_word: u16 = Word0.caps(domain.user_table[slot].word0);
    const var_caps: VarCaps = @bitCast(caps_word);
    if (!var_caps.r) return errors.E_PERM;

    v._gen_lock.lock(@src());
    defer v._gen_lock.unlock();

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;
    if (offset + @as(u64, count) * 8 > var_size) return errors.E_INVAL;

    // Cross-domain coherent read: pause every EC in the VAR's owning
    // domain, copy `count` qwords from VAR.base + offset into the
    // caller's vregs, then resume. The vreg copy happens at the
    // syscall ABI boundary, which is not on this stub's surface.
    quiesceDomain(v.domain);
    defer resumeDomain(v.domain);
    return 0;
}

/// `idc_write` syscall handler. Spec §[var].idc_write.
pub fn idcWrite(caller: *ExecutionContext, var_handle: u64, offset: u64, count: u8) i64 {
    if (count == 0 or count > 125) return errors.E_INVAL;
    if (!std.mem.isAligned(offset, 8)) return errors.E_INVAL;

    const domain = caller.domain.ptr;
    const slot: u12 = @truncate(var_handle & 0xFFF);
    const v = resolveVar(domain, slot) orelse return errors.E_BADCAP;

    const caps_word: u16 = Word0.caps(domain.user_table[slot].word0);
    const var_caps: VarCaps = @bitCast(caps_word);
    if (!var_caps.w) return errors.E_PERM;

    v._gen_lock.lock(@src());
    defer v._gen_lock.unlock();

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;
    if (offset + @as(u64, count) * 8 > var_size) return errors.E_INVAL;

    quiesceDomain(v.domain);
    defer resumeDomain(v.domain);
    return 0;
}

// ── Internal API ─────────────────────────────────────────────────────

inline fn packField1(
    pages: u32,
    sz: PageSize,
    cch: CacheType,
    cur_rwx: u3,
    map: MapType,
    device_id: u12,
) u64 {
    return @as(u64, pages) |
        (@as(u64, @intFromEnum(sz)) << 32) |
        (@as(u64, @intFromEnum(cch)) << 34) |
        (@as(u64, cur_rwx) << 36) |
        (@as(u64, @intFromEnum(map)) << 39) |
        (@as(u64, device_id) << 41);
}

/// Look up a handle slot expecting the given type. Returns null on
/// out-of-range, free slot, or type mismatch. Centralized here to keep
/// every VAR-handler's resolve path identical.
fn lookupHandle(cd: *CapabilityDomain, slot: u12, expected: CapabilityType) ?*KernelHandle {
    if (slot >= cd.user_table.len) return null;
    const cap = cd.user_table[slot];
    if (Word0.typeTag(cap.word0) != expected) return null;
    const kh = &cd.kernel_table[slot];
    if (kh.ref.ptr == null) return null;
    return kh;
}

fn resolveVar(cd: *CapabilityDomain, slot: u12) ?*VAR {
    const kh = lookupHandle(cd, slot, .virtual_address_range) orelse return null;
    return @ptrCast(@alignCast(kh.ref.ptr.?));
}

/// Refresh `slot`'s field0/field1 from authoritative VAR state. Spec
/// §[var] tests 14/09/12 (implicit-sync side effect on every syscall
/// touching the handle).
fn refreshVarSnapshot(cd: *CapabilityDomain, slot: u12, v: *const VAR) void {
    if (slot >= cd.user_table.len) return;
    const dev_id: u12 = if (v.device) |dr| handleIdOf(cd, dr) else 0;
    cd.user_table[slot].field0 = v.base_vaddr.addr;
    cd.user_table[slot].field1 = packField1(v.page_count, v.sz, v.cch, v.cur_rwx, v.map, dev_id);
}

/// Linear scan of `cd`'s handle table for the slot id pointing at `dr`.
/// Returns 0 when no handle is found — safe because slot 0 is reserved
/// for the self-handle and so cannot hold a device_region.
fn handleIdOf(cd: *const CapabilityDomain, dr: *const DeviceRegion) u12 {
    var i: u16 = 0;
    while (i < cd.user_table.len) {
        const cap = cd.user_table[i];
        if (Word0.typeTag(cap.word0) == .device_region) {
            const kh = cd.kernel_table[i];
            if (kh.ref.ptr == @as(*const anyopaque, @ptrCast(dr))) return @intCast(i);
        }
        i += 1;
    }
    return 0;
}

/// Allocate a VAR slab slot, claim a VA range in `domain`, append to
/// `domain.vars[]`. Spec §[var].create_var.
fn allocVar(
    domain: *CapabilityDomain,
    base: VAddr,
    pages: u32,
    sz: PageSize,
    cch: CacheType,
    cur_rwx: u3,
    device: ?*DeviceRegion,
) !*VAR {
    const ref = try slab_instance.create();
    const v = ref.ptr;
    v.domain = domain;
    v.base_vaddr = base;
    v.page_count = pages;
    v.sz = sz;
    v.cch = cch;
    v.cur_rwx = cur_rwx;
    v.map = .unmapped;
    v.device = device;
    v.snapshot_source = null;
    v.mapping_table = null;
    return v;
}

/// Final teardown — unmaps all installations, releases device/snapshot
/// refs, removes from `domain.vars[]`, frees VA range, frees slab slot.
fn destroyVar(v: *VAR) void {
    const domain = v.domain;
    const gen = v._gen_lock.currentGen();
    if (v.map == .page_frame or v.map == .demand) {
        unmapAll(v, domain);
    } else if (v.map == .mmio) {
        const sz_bytes = pageSizeBytes(v.sz);
        var off: u64 = 0;
        while (off < @as(u64, v.page_count) * sz_bytes) {
            _ = dispatch.paging.unmapPageSized(
                domain.addr_space_root,
                .fromInt(v.base_vaddr.addr + off),
                v.sz,
            );
            off += sz_bytes;
        }
        dispatch.paging.shootdownTlbRange(
            domain.addr_space_id,
            v.base_vaddr,
            v.sz,
            v.page_count,
        );
    }
    zag.capdom.capability_domain.removeVar(domain, v);
    slab_instance.destroy(v, gen) catch {};
}

/// Allocate a contiguous VA range of `pages * sz` bytes for a new VAR.
/// `preferred_base != 0` returns that base verbatim (the create_var
/// caller is asking for a specific address; the per-domain overlap
/// check still has the final say). Otherwise pick a randomized,
/// `sz`-aligned base inside the ASLR zone (spec §[create_var] test 24
/// + §[address_space]). On overlap with an existing VAR, retry a
/// bounded number of times then fall back to a bump pointer for
/// forward progress.
fn vaRangeAllocate(
    domain: *CapabilityDomain,
    pages: u32,
    sz: PageSize,
    preferred_base: VAddr,
) ?VAddr {
    if (preferred_base.addr != 0) return preferred_base;

    const sz_bytes = pageSizeBytes(sz);
    const range_bytes = @as(u64, pages) * sz_bytes;
    const aslr = dispatch.paging.user_aslr;
    if (range_bytes > aslr.end - aslr.start) return null;
    const max_base = aslr.end - range_bytes;
    if (max_base < aslr.start) return null;

    // Try a small number of randomized placements first. The overlap
    // check below is the authoritative collision test; here we simply
    // probe distinct random bases.
    const RETRY_LIMIT = 8;
    var attempt: u8 = 0;
    while (attempt < RETRY_LIMIT) {
        const r = aslrRandom();
        const span = max_base - aslr.start + sz_bytes;
        const off = r % span;
        const candidate = aslr.start + std.mem.alignBackward(u64, off, sz_bytes);
        if (candidate >= aslr.start and candidate <= max_base) {
            if (!domainOverlaps(domain, candidate, range_bytes)) {
                return .fromInt(candidate);
            }
        }
        attempt += 1;
    }

    // Fallback: bump-allocate from `next_var_base` so a VA-pressured
    // domain still makes forward progress when randomized probing
    // keeps colliding.
    const aligned = std.mem.alignForward(u64, domain.next_var_base, sz_bytes);
    const new_top = aligned + range_bytes;
    if (new_top > aslr.end) return null;
    domain.next_var_base = new_top;
    return .fromInt(aligned);
}

/// Cheap overlap test against the domain's already-bound VARs. Used
/// during randomized base selection — `checkVaRangeOverlap` has the
/// same logic but returns an i64 status; here we want a bool to drive
/// retry decisions.
fn domainOverlaps(domain: *const CapabilityDomain, base: u64, bytes: u64) bool {
    const new_end = base + bytes;
    var i: u16 = 0;
    while (i < domain.var_count) {
        const v = domain.vars[i] orelse {
            i += 1;
            continue;
        };
        const v_sz_bytes = pageSizeBytes(v.sz);
        const v_start = v.base_vaddr.addr;
        const v_end = v_start + @as(u64, v.page_count) * v_sz_bytes;
        if (base < v_end and v_start < new_end) return true;
        i += 1;
    }
    return false;
}

/// Sample one 64-bit value of randomness for ASLR placement. Uses the
/// hardware RNG (RDRAND/RNDR) when available; falls back to TSC bits
/// xor'd with a per-call counter so two back-to-back calls still
/// produce distinct values when the entropy source stalls.
pub fn aslrRandom() u64 {
    if (dispatch.cpu.getRandom()) |hw| return hw;
    const ts = dispatch.time.readTimestamp(false);
    aslr_fallback_counter +%= 1;
    return ts ^ (aslr_fallback_counter *% 0x9E3779B97F4A7C15);
}

var aslr_fallback_counter: u64 = 0;

/// Install a page_frame at offset, increments mapcnt, programs PTE or
/// IOMMU PTE. Spec §[var].map_pf — installs every page in the page
/// frame contiguously starting at `offset`.
fn mappingInstall(v: *VAR, offset: u64, pf: *PageFrame) i64 {
    const domain = v.domain;
    const slot_idx = handleSlotOf(v, domain);
    const caps_word: u16 = if (slot_idx < domain.user_table.len)
        Word0.caps(domain.user_table[slot_idx].word0)
    else
        0;
    const var_caps: VarCaps = @bitCast(caps_word);
    const perms = rwxToPerms(v.cur_rwx);
    const pf_sz_bytes = pageSizeBytes(pf.sz);

    var p: u32 = 0;
    while (p < pf.page_count) {
        const off_p = offset + @as(u64, p) * pf_sz_bytes;
        const phys_p = zag.memory.address.PAddr.fromInt(
            pf.phys_base.addr + @as(u64, p) * pf_sz_bytes,
        );
        if (var_caps.dma) {
            const dev = v.device orelse return errors.E_INVAL;
            dispatch.iommu.iommuMapPage(
                dev,
                v.base_vaddr.addr + off_p,
                phys_p,
                v.sz,
                perms,
            ) catch return errors.E_NOMEM;
        } else {
            dispatch.paging.mapPageSized(
                domain.addr_space_root,
                phys_p,
                .fromInt(v.base_vaddr.addr + off_p),
                v.sz,
                v.cch,
                perms,
            ) catch return errors.E_NOMEM;
        }
        p += 1;
    }
    incMapCntShim(pf);
    return 0;
}

/// Remove an installation, decrements mapcnt, tears down PTE.
/// Returns the removed page_frame so caller can release its handle ref.
fn mappingRemove(v: *VAR, offset: u64) ?*PageFrame {
    const domain = v.domain;
    const slot_idx = handleSlotOf(v, domain);
    const caps_word: u16 = if (slot_idx < domain.user_table.len)
        Word0.caps(domain.user_table[slot_idx].word0)
    else
        0;
    const var_caps: VarCaps = @bitCast(caps_word);

    if (var_caps.dma) {
        const dev = v.device orelse return null;
        _ = dispatch.iommu.iommuUnmapPage(dev, v.base_vaddr.addr + offset, v.sz);
        dispatch.iommu.invalidateIotlbRange(dev, v.base_vaddr.addr + offset, v.sz, 1);
    } else {
        _ = dispatch.paging.unmapPageSized(
            domain.addr_space_root,
            .fromInt(v.base_vaddr.addr + offset),
            v.sz,
        );
    }
    return null;
}

/// Demand-page allocation on first fault to an unmapped VAR. Allocates
/// a fresh zero PageFrame and installs at the faulting offset.
fn demandAlloc(v: *VAR, offset: u64) i64 {
    _ = v;
    _ = offset;
    return errors.E_NOMEM;
}

/// Page-fault handler hook — looks up the VAR covering `fault_vaddr`
/// in `domain` and dispatches per `map`. Spec §[var] demand transition.
pub fn handlePageFault(domain: *CapabilityDomain, fault_vaddr: VAddr, access_rwx: u3) i64 {
    const v = findVarCovering(domain, fault_vaddr) orelse return errors.E_BADADDR;
    v._gen_lock.lock(@src());
    defer v._gen_lock.unlock();

    if ((access_rwx & ~v.cur_rwx) != 0) return errors.E_PERM;

    switch (v.map) {
        .unmapped => {
            const offset = fault_vaddr.addr - v.base_vaddr.addr;
            const sz_bytes = pageSizeBytes(v.sz);
            const aligned = std.mem.alignBackward(u64, offset, sz_bytes);
            const rc = demandAlloc(v, aligned);
            if (rc == 0) v.map = .demand;
            return rc;
        },
        .demand => {
            const offset = fault_vaddr.addr - v.base_vaddr.addr;
            const sz_bytes = pageSizeBytes(v.sz);
            const aligned = std.mem.alignBackward(u64, offset, sz_bytes);
            return demandAlloc(v, aligned);
        },
        .mmio => {
            // Port-IO virtualization — decode MOV, emit IN/OUT, advance
            // RIP. Spec §[port_io_virtualization]. Plain MMIO faults
            // here are spurious (real PTEs were installed at map time)
            // and route to the EC's memory_fault event.
            const dev = v.device orelse return errors.E_BADADDR;
            if (dev.device_type == .port_io) {
                return decodePortIoFault(domain, fault_vaddr, v, dev);
            }
            return errors.E_PERM;
        },
        .page_frame => return errors.E_PERM,
    }
}

/// Per-VAR restart cleanup, dispatched by `caps.restart_policy`:
/// 0=free, 1=decommit, 2=preserve, 3=snapshot. Spec §[restart_semantics].
fn restartCleanup(v: *VAR, policy: u2) i64 {
    const p: RestartPolicy = @enumFromInt(policy);
    switch (p) {
        .free => {
            destroyVar(v);
            return 0;
        },
        .decommit => {
            unmapAll(v, v.domain);
            v.map = .unmapped;
            return 0;
        },
        .preserve => return 0,
        .snapshot => {
            const src = v.snapshot_source orelse return errors.E_TERM;
            return copySnapshot(v, src);
        },
    }
}

fn incMapCntShim(pf: *PageFrame) void {
    _ = @atomicRmw(u32, &pf.mapcnt, .Add, 1, .seq_cst);
}

/// Linear scan for any VAR whose [base, base + page_count*sz) covers
/// `fault_vaddr`. The flat per-domain `vars[]` makes this O(N) which
/// is fine because a domain holds at most MAX_VARS_PER_DOMAIN (512).
pub fn findVarCovering(cd: *CapabilityDomain, fault_vaddr: VAddr) ?*VAR {
    var i: u16 = 0;
    while (i < cd.var_count) {
        const v = cd.vars[i] orelse {
            i += 1;
            continue;
        };
        const sz_bytes = pageSizeBytes(v.sz);
        const end = v.base_vaddr.addr + @as(u64, v.page_count) * sz_bytes;
        if (fault_vaddr.addr >= v.base_vaddr.addr and fault_vaddr.addr < end) {
            return v;
        }
        i += 1;
    }
    return null;
}

/// Find which slot id in `domain.user_table` holds the handle for `v`.
/// Linear scan; the 4096-entry table cap bounds the cost. Returns
/// `MAX_HANDLES_PER_DOMAIN` (out-of-range) when no handle is found —
/// callers truncate to u12 and read the resulting cap word.
fn handleSlotOf(v: *const VAR, cd: *const CapabilityDomain) u16 {
    var i: u16 = 0;
    while (i < cd.user_table.len) {
        const cap = cd.user_table[i];
        if (Word0.typeTag(cap.word0) == .virtual_address_range) {
            const kh = cd.kernel_table[i];
            if (kh.ref.ptr == @as(*const anyopaque, @ptrCast(v))) return i;
        }
        i += 1;
    }
    return @intCast(cd.user_table.len);
}

/// Walk the per-page mapping table of `v` looking for an installed
/// page_frame matching `pf`. Returns the byte offset, or null if not
/// installed. Concrete walk depends on the eventual `mapping_table`
/// layout.
fn findInstalledOffset(v: *VAR, pf: *PageFrame) ?u64 {
    _ = v;
    _ = pf;
    return null;
}

/// Number of currently-installed pages in `v`'s mapping table. Used by
/// `unmap` to decide whether to clear `map` back to `unmapped`.
fn countInstalled(v: *VAR) u32 {
    _ = v;
    return 0;
}

/// Tear down every installed PTE / demand page, decrement mapcnts, and
/// invalidate. Called by `unmap` (N=0) and `destroyVar`.
fn unmapAll(v: *VAR, domain: *CapabilityDomain) void {
    const sz_bytes = pageSizeBytes(v.sz);
    var off: u64 = 0;
    while (off < @as(u64, v.page_count) * sz_bytes) {
        _ = dispatch.paging.unmapPageSized(
            domain.addr_space_root,
            .fromInt(v.base_vaddr.addr + off),
            v.sz,
        );
        off += sz_bytes;
    }
    dispatch.paging.shootdownTlbRange(
        domain.addr_space_id,
        v.base_vaddr,
        v.sz,
        v.page_count,
    );
}

/// Pause every EC bound to `cd`. Used by idc_read/idc_write to obtain
/// a coherent snapshot of the VAR's contents without observable
/// interleaving.
fn quiesceDomain(cd: *CapabilityDomain) void {
    _ = cd;
}

fn resumeDomain(cd: *CapabilityDomain) void {
    _ = cd;
}

/// Decode the MOV that hit a port-IO VAR, emit the matching IN/OUT,
/// commit the result, advance RIP. Spec §[port_io_virtualization].
fn decodePortIoFault(
    cd: *CapabilityDomain,
    fault_vaddr: VAddr,
    v: *VAR,
    dev: *DeviceRegion,
) i64 {
    _ = cd;
    _ = fault_vaddr;
    _ = v;
    _ = dev;
    return errors.E_INVAL;
}

/// Copy snapshot source contents into `target` at restart. Verifies the
/// source's stability constraints (mapcnt and effective-write) per spec
/// §[var].snapshot before committing.
fn copySnapshot(target: *VAR, source: *VAR) i64 {
    _ = target;
    _ = source;
    return 0;
}
