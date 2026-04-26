//! Capability domain — set of capabilities usable by execution contexts
//! bound to the domain. See docs/kernel/specv3.md §[capability_domain].
//!
//! Owns:
//!   - Address space (page tables + PCID/ASID)
//!   - Two parallel handle tables (user-visible + kernel-side mirror)
//!   - Flat list of bound VARs
//!   - Optional bound VM
//!
//! All per-domain ceilings (ec_inner/outer, var_inner/outer, cridc, idc_rx,
//! pf, vm, port, restart_policy, fut_wait_max) live in the self-handle at
//! slot 0 of the handle table — kernel reads them from `user_table[0]`
//! like anyone else, no duplication on the struct.
//!
//! ECs bound to this domain are reachable through the handle table (walk
//! looking for type = execution_context) and through whatever pins them
//! (run queue, port wait queue, etc.). No separate ECs array — the spec's
//! `acquire_ecs` is an explicitly slow debugger primitive, the linear walk
//! is fine for it.
//!
//! STUB. Forward refs to VAR and VirtualMachine point at intended future
//! paths.

const zag = @import("zag");

const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const pmm = zag.memory.pmm;

const Capability = zag.caps.capability.Capability;
const CapabilityType = zag.caps.capability.CapabilityType;
const ErasedSlabRef = zag.caps.capability.ErasedSlabRef;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const KernelHandle = zag.caps.capability.KernelHandle;
const PAddr = zag.memory.address.PAddr;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const VAR = zag.capdom.var_range.VAR;
const VAddr = zag.memory.address.VAddr;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const Word0 = zag.caps.capability.Word0;

/// Cap bits in `Capability.word0[48..63]` for the capability_domain
/// self-handle (slot 0). Spec §[capability_domain] self handle.
pub const CapabilityDomainCaps = packed struct(u16) {
    crcd: bool = false,
    crec: bool = false,
    crvr: bool = false,
    crpf: bool = false,
    crvm: bool = false,
    crpt: bool = false,
    pmu: bool = false,
    setwall: bool = false,
    power: bool = false,
    restart: bool = false,
    reply_policy: bool = false,
    fut_wake: bool = false,
    timer: bool = false,
    _reserved: u1 = 0,
    pri: u2 = 0,
};

/// Cap bits in `Capability.word0[48..63]` for IDC (capability_domain)
/// handles. Spec §[capability_domain] IDC handle.
pub const IdcCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    crec: bool = false,
    aqec: bool = false,
    aqvr: bool = false,
    restart_policy: u1 = 0,
    _reserved: u10 = 0,
};

const MAX_HANDLES_PER_DOMAIN = zag.caps.capability.MAX_HANDLES_PER_DOMAIN;
const FREE_LIST_TAIL = zag.caps.capability.FREE_LIST_TAIL;

/// Maximum VARs bindable to a single capability domain. 512 × 8 bytes
/// = 4 KiB inline. Coarse upper bound; well above realistic per-domain
/// VAR counts (a domain with even a few dozen VARs is unusual).
pub const MAX_VARS_PER_DOMAIN: u16 = 512;

pub const CapabilityDomain = struct {
    /// Slab generation lock. Validates `SlabRef(CapabilityDomain)`
    /// liveness AND guards every mutable field below.
    _gen_lock: GenLock = .{},

    // ── Address space ─────────────────────────────────────────────────

    /// Physical address of this domain's top-level page table (PML4 on
    /// x86-64, TTBR on aarch64). Set at create; immutable.
    addr_space_root: PAddr,

    /// PCID (x86-64) / ASID (aarch64) tag. Set at create; immutable.
    /// Used as the low 12 bits of CR3 (with PCIDE=1) so address-space
    /// switches don't flush TLB entries from other domains.
    addr_space_id: u16,

    // ── Handle tables ────────────────────────────────────────────────
    //
    // Two parallel arrays of MAX_HANDLES_PER_DOMAIN entries, indexed by
    // the same 12-bit handle id.
    //
    //   user_table   — 96 KiB. Mapped read-only into this domain so
    //                  userspace can read cap word + field0/field1 of
    //                  any handle without a syscall. Kernel writes
    //                  field0/field1 to refresh kernel-mutable
    //                  snapshots (EC priority/affinity, VAR cur_rwx,
    //                  device IRQ counters, etc.) directly through
    //                  the kernel R/W view of the same physical pages.
    //
    //   kernel_table — kernel-only. Holds ErasedSlabRef + revoke
    //                  ancestry tree links (parent / first_child /
    //                  next_sibling) when used, with `parent` doubling
    //                  as the free-slot list link when free.
    //
    // Pointer-based rather than inline so the domain struct itself
    // stays slab-allocatable. Tables are page-aligned PMM allocations
    // made at create_capability_domain time.

    user_table: *[MAX_HANDLES_PER_DOMAIN]Capability,
    kernel_table: *[MAX_HANDLES_PER_DOMAIN]KernelHandle,

    /// Head of the free-slot list. `FREE_LIST_TAIL` (0xFFFF) when the
    /// table is full. Free entries store the next-free slot index in
    /// `kernel_table[i].parent.slot` (see `KernelHandle` doc), terminated
    /// by `FREE_LIST_TAIL`.
    free_head: u16 = FREE_LIST_TAIL,

    /// Number of free slots. Lets `copy`/`acquire_*` early-bail with
    /// `E_FULL` without walking the free list.
    free_count: u16 = MAX_HANDLES_PER_DOMAIN,

    // ── Bound VARs ───────────────────────────────────────────────────

    /// Flat array of VARs bound to this domain. Used for:
    ///   - VA-range overlap check at `create_var` (linear scan)
    ///   - Enumeration via `acquire_vars` (debugger primitive)
    ///   - Walk-and-free at domain destroy
    /// Entries `[0..var_count)` are populated; entries beyond are null.
    /// On removal the tail is moved into the freed slot to keep the
    /// populated prefix dense (no holes to skip).
    vars: [MAX_VARS_PER_DOMAIN]?*VAR = .{null} ** MAX_VARS_PER_DOMAIN,

    /// Number of populated entries in `vars`. Range 0..MAX_VARS_PER_DOMAIN.
    var_count: u16 = 0,

    // ── Bound VM ─────────────────────────────────────────────────────

    /// VM bound to this domain. Capability-domain lifetime; at most
    /// one per spec (the VM handle is non-transferable, exactly one
    /// holder = the binding domain). `null` on non-VM domains.
    vm: ?*VirtualMachine = null,
};

pub const Allocator = SecureSlab(CapabilityDomain, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

// ── External API ─────────────────────────────────────────────────────

/// `create_capability_domain` syscall handler.
/// Spec §[capability_domain].create_capability_domain.
pub fn createCapabilityDomain(
    caller: *ExecutionContext,
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf: u64,
    passed_handles: []const u64,
) i64 {
    _ = caller;
    _ = caps;
    _ = ceilings_inner;
    _ = ceilings_outer;
    _ = elf_pf;
    _ = passed_handles;
    return -1;
}

/// `acquire_ecs` syscall handler.
/// Spec §[capability_domain].acquire_ecs.
pub fn acquireEcs(caller: *ExecutionContext, target_idc: u64) i64 {
    _ = caller;
    _ = target_idc;
    return -1;
}

/// `acquire_vars` syscall handler.
/// Spec §[capability_domain].acquire_vars.
pub fn acquireVars(caller: *ExecutionContext, target_idc: u64) i64 {
    _ = caller;
    _ = target_idc;
    return -1;
}

// ── Internal API ─────────────────────────────────────────────────────

/// Round handle-table size up to a power-of-two-page block. Buddy
/// `allocBlock` requires power-of-two multiples of 4 KiB. Wastes some
/// memory at the tail but keeps the alloc path simple.
fn handleTableBlockBytes(comptime T: type) u64 {
    const raw: u64 = @as(u64, MAX_HANDLES_PER_DOMAIN) * @sizeOf(T);
    const pages: u64 = (raw + 0xFFF) / 0x1000;
    var pow: u64 = 1;
    while (pow < pages) pow <<= 1;
    return pow * 0x1000;
}

const USER_TABLE_BYTES: u64 = handleTableBlockBytes(Capability);
const KERNEL_TABLE_BYTES: u64 = handleTableBlockBytes(KernelHandle);

/// Allocate a new CapabilityDomain — slab slot, handle tables from PMM,
/// address-space root, slot-0 self-handle, slot-1 placeholder for the
/// initial EC handle (filled by caller via `mintHandle`), slot-2 self-IDC.
/// Spec §[capability_domain].
pub fn allocCapabilityDomain(
    self_caps: u16,
    field0_ceilings: u64,
    field1_ceilings: u64,
    initial_entry: VAddr,
) !*CapabilityDomain {
    _ = initial_entry;

    const ref = try slab_instance.create();
    const cd = ref.ptr;
    errdefer slab_instance.destroy(cd, cd._gen_lock.currentGen()) catch {};

    const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;

    // Handle tables live in kernel physmap RAM. PMM zero-on-free
    // guarantees the pages come up cleared.
    const user_buf = pmm_mgr.allocBlock(USER_TABLE_BYTES) orelse return error.OutOfMemory;
    errdefer pmm_mgr.freeBlock(user_buf[0..USER_TABLE_BYTES]);
    const kernel_buf = pmm_mgr.allocBlock(KERNEL_TABLE_BYTES) orelse return error.OutOfMemory;
    errdefer pmm_mgr.freeBlock(kernel_buf[0..KERNEL_TABLE_BYTES]);

    const user_table: *[MAX_HANDLES_PER_DOMAIN]Capability = @ptrCast(@alignCast(user_buf));
    const kernel_table: *[MAX_HANDLES_PER_DOMAIN]KernelHandle = @ptrCast(@alignCast(kernel_buf));

    cd.user_table = user_table;
    cd.kernel_table = kernel_table;

    // Free-list links cover slots 3..MAX-1; slots 0/1/2 are reserved by
    // spec and are NOT on the free list.
    var i: u16 = 3;
    while (i < MAX_HANDLES_PER_DOMAIN - 1) {
        kernel_table[i].parent = zag.caps.capability.encodeFreeNext(i + 1);
        i += 1;
    }
    kernel_table[MAX_HANDLES_PER_DOMAIN - 1].parent =
        zag.caps.capability.encodeFreeNext(zag.caps.capability.FREE_LIST_TAIL);
    cd.free_head = 3;
    cd.free_count = MAX_HANDLES_PER_DOMAIN - 3;
    cd.var_count = 0;
    cd.vm = null;
    @memset(cd.vars[0..], null);

    // Address space root + ASID. The new domain needs a fresh page-table
    // root so the ELF + handle tables can be installed; the ASID tags TLB
    // entries.
    cd.addr_space_root = try arch.paging.allocAddrSpaceRoot();
    cd.addr_space_id = arch.paging.allocAddrSpaceId() orelse 0;

    // Slot 0 — self-handle. Carries ceilings + caps; the rest of the
    // kernel reads them back through `user_table[0]` per the doc on
    // `CapabilityDomain.user_table`.
    user_table[0].word0 = Word0.pack(0, .capability_domain_self, self_caps);
    user_table[0].field0 = field0_ceilings;
    user_table[0].field1 = field1_ceilings;
    kernel_table[0].ref = .{
        .ptr = cd,
        .gen = @intCast(cd._gen_lock.currentGen()),
    };

    // Slot 1 — placeholder for the initial EC handle; populated by the
    // caller (root bringup or `create_capability_domain`).
    user_table[1] = .{ .word0 = 0, .field0 = 0, .field1 = 0 };
    kernel_table[1].ref = .{};

    // Slot 2 — self-IDC. Caps = `cridc_ceiling` from field0_ceilings
    // bits 24-31 per spec §[cridc_ceiling].
    const cridc_ceiling: u16 = @truncate((field0_ceilings >> 24) & 0xFF);
    user_table[2].word0 = Word0.pack(2, .capability_domain, cridc_ceiling);
    user_table[2].field0 = 0;
    user_table[2].field1 = 0;
    kernel_table[2].ref = .{
        .ptr = cd,
        .gen = @intCast(cd._gen_lock.currentGen()),
    };

    return cd;
}

/// Final teardown — walks `vars` freeing each VAR, walks
/// `kernel_table` releasing every used slot per type, tears down the
/// address space, frees the table pages, frees slab.
fn destroyCapabilityDomain(cd: *CapabilityDomain) void {
    _ = cd;
}

/// Pop the head of the free-slot list. Returns `null` (E_FULL) if the
/// table is full.
fn allocFreeSlot(cd: *CapabilityDomain) ?u12 {
    if (cd.free_count == 0) return null;
    const head = cd.free_head;
    if (head == zag.caps.capability.FREE_LIST_TAIL) return null;
    const slot: u12 = @truncate(head);
    const next = zag.caps.capability.decodeFreeNext(cd.kernel_table[slot].parent);
    cd.free_head = next;
    cd.free_count -= 1;
    return slot;
}

/// Push a slot back onto the free-slot list. Zeros the user/kernel
/// entries.
fn returnSlotToFreeList(cd: *CapabilityDomain, slot: u12) void {
    cd.user_table[slot] = .{ .word0 = 0, .field0 = 0, .field1 = 0 };
    cd.kernel_table[slot].ref = .{};
    cd.kernel_table[slot].parent = zag.caps.capability.encodeFreeNext(cd.free_head);
    cd.kernel_table[slot].first_child = .{};
    cd.kernel_table[slot].next_sibling = .{};
    cd.free_head = @as(u16, slot);
    cd.free_count += 1;
}

/// Look up a slot, validate type tag against `expected`, return the
/// kernel-side entry. Returns null on free-slot, out-of-range, or
/// type mismatch.
fn lookupSlot(cd: *CapabilityDomain, slot: u12, expected: CapabilityType) ?*KernelHandle {
    return zag.caps.capability.resolveHandleOnDomain(cd, slot, expected);
}

/// Linear scan for an existing handle to `obj` in this domain, used
/// to enforce the at-most-one-per-(domain, object) invariant.
/// Returns the existing slot id if found.
fn findExistingHandle(cd: *CapabilityDomain, obj: ErasedSlabRef, t: CapabilityType) ?u12 {
    var i: u16 = 0;
    while (i < MAX_HANDLES_PER_DOMAIN) {
        const entry = &cd.kernel_table[i];
        if (entry.ref.ptr != null and entry.ref.ptr == obj.ptr and entry.ref.gen == obj.gen) {
            const tag = Word0.typeTag(cd.user_table[i].word0);
            if (tag == t) return @truncate(i);
        }
        i += 1;
    }
    return null;
}

/// Mint a handle into `cd`'s table at a fresh slot. Allocates from the
/// free list, writes both halves, returns the slot id. Coalesces with
/// existing handle to the same object per the at-most-one invariant.
pub fn mintHandle(
    cd: *CapabilityDomain,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) !u12 {
    if (findExistingHandle(cd, obj, obj_type)) |existing| {
        // Coalesce: keep the original entry, return its slot. Spec
        // semantics: at most one handle per (domain, object).
        return existing;
    }

    const slot = allocFreeSlot(cd) orelse return error.OutOfHandles;
    cd.user_table[slot].word0 = Word0.pack(slot, obj_type, caps);
    cd.user_table[slot].field0 = field0;
    cd.user_table[slot].field1 = field1;
    cd.kernel_table[slot].ref = obj;
    cd.kernel_table[slot].parent = .{};
    cd.kernel_table[slot].first_child = .{};
    cd.kernel_table[slot].next_sibling = .{};
    return slot;
}

/// Read a self-handle ceiling sub-field. All ceilings live in slot-0's
/// `field0`/`field1`; centralized here so future spec changes touch
/// one place.
fn readSelfField0(cd: *const CapabilityDomain) u64 {
    return cd.user_table[0].field0;
}
fn readSelfField1(cd: *const CapabilityDomain) u64 {
    return cd.user_table[0].field1;
}
fn readSelfCaps(cd: *const CapabilityDomain) u16 {
    return Word0.caps(cd.user_table[0].word0);
}

/// Append `v` to `vars[var_count]`. Returns E_FULL when at MAX.
pub fn appendVar(cd: *CapabilityDomain, v: *VAR) i64 {
    if (cd.var_count >= cd.vars.len) return errors.E_FULL;
    cd.vars[cd.var_count] = v;
    cd.var_count += 1;
    return 0;
}

/// Remove `v` from `vars` by tail-swap; decrements var_count.
pub fn removeVar(cd: *CapabilityDomain, v: *VAR) void {
    var i: u16 = 0;
    while (i < cd.var_count) {
        if (cd.vars[i] == v) {
            cd.var_count -= 1;
            cd.vars[i] = cd.vars[cd.var_count];
            cd.vars[cd.var_count] = null;
            return;
        }
        i += 1;
    }
}

/// Linear-scan `vars[]` for any range overlapping `[base, base + bytes)`.
/// Returns E_NOSPC on overlap, 0 otherwise. Spec §[var].create_var.
pub fn checkVaRangeOverlap(cd: *const CapabilityDomain, base: VAddr, bytes: u64) i64 {
    const new_start = base.addr;
    const new_end = new_start + bytes;
    var i: u16 = 0;
    while (i < cd.var_count) {
        const v = cd.vars[i] orelse {
            i += 1;
            continue;
        };
        const sz_bytes: u64 = switch (v.sz) {
            .sz_4k => 0x1000,
            .sz_2m => 0x20_0000,
            .sz_1g => 0x4000_0000,
            ._reserved => 0,
        };
        const v_start = v.base_vaddr.addr;
        const v_end = v_start + @as(u64, v.page_count) * sz_bytes;
        if (new_start < v_end and v_start < new_end) return errors.E_NOSPC;
        i += 1;
    }
    return 0;
}

/// Top-level domain restart driver. Walks handle table applying per-
/// handle restart_policy, copies snapshot-bound VARs, re-launches ECs.
/// Returns negative E_TERM on unrecoverable failure (caller tears down).
pub fn restartDomain(cd: *CapabilityDomain) i64 {
    _ = cd;
    return -1;
}

/// Public release-handle entry point invoked when `delete` is called
/// on the domain's self-handle. Wraps `destroyCapabilityDomain`.
pub fn releaseSelf(cd: *CapabilityDomain) void {
    _ = cd;
    @panic("not implemented");
}
