const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const kprof = zag.kprof.trace_id;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const secure_slab = zag.memory.allocators.secure_slab;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const GenLock = secure_slab.GenLock;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PrivilegePerm = zag.perms.privilege.PrivilegePerm;
const SharedMemory = zag.memory.shared.SharedMemory;
const SlabRef = secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;
const VmReservationRights = zag.perms.permissions.VmReservationRights;

pub const HANDLE_NONE: u64 = std.math.maxInt(u64);

/// Per-process reservation cap. Reservations live in a sorted inline
/// `[MAX_RESERVATIONS]SlabRef(VmNode)` array inside every process's VMM —
/// lookups are `std.sort.lowerBound` (O(log N) with cache-friendly
/// contiguous memory), insert/remove are `@memmove` of the tail (O(N)
/// but N ≤ 256 and the compiler vectorizes the shift). Every reservation
/// type stacks the same way: private ranges, SHM maps, MMIO maps,
/// virtual-BAR maps, kernel reservations, plus the underflow/overflow
/// guards around each user stack.
pub const MAX_RESERVATIONS: usize = 256;

pub const RestartPolicy = enum(u8) {
    free,
    decommit,
    preserve,
};

pub const VmNodeKind = enum(u8) {
    private = 0,
    shared_memory = 1,
    mmio = 2,
    virtual_bar = 3,
};

/// Type-erased payload for `VmNode.kind_ptr`:
///   .private               → kind_ptr == null
///   .shared_memory         → kind_ptr points at the backing *SharedMemory
///   .mmio, .virtual_bar    → kind_ptr points at the backing *DeviceRegion
///
/// Split from a tagged union so VmNode can be `extern struct` and carry
/// the slab-allocator gen-lock at offset 0.
pub const VmNode = extern struct {
    _gen_lock: GenLock = .{},
    start: VAddr,
    size: u64,
    handle: u64,
    kind_ptr: ?*anyopaque,
    rights: VmReservationRights,
    kind: VmNodeKind,
    restart_policy: RestartPolicy,
    _pad: [5]u8 = .{ 0, 0, 0, 0, 0 },

    pub fn end(self: *const VmNode) u64 {
        return self.start.addr + self.size;
    }

    /// Populate every non-`_gen_lock` field of a freshly allocated node.
    /// Use this instead of `node.* = .{...}` — a whole-struct assignment
    /// would clobber the gen-lock word that the allocator just set.
    pub fn init(self: *VmNode, start: VAddr, size: u64, kind: VmNodeKind, kind_ptr: ?*anyopaque, rights: VmReservationRights, handle: u64, policy: RestartPolicy) void {
        self.start = start;
        self.size = size;
        self.kind = kind;
        self.kind_ptr = kind_ptr;
        self.rights = rights;
        self.handle = handle;
        self.restart_policy = policy;
        // Explicit pad reset: a recycled slot would otherwise carry
        // whatever the previous occupant left in these bytes.
        self._pad = .{ 0, 0, 0, 0, 0 };
    }

    pub fn sharedMemory(self: *const VmNode) ?*SharedMemory {
        if (self.kind != .shared_memory) return null;
        return @ptrCast(@alignCast(self.kind_ptr));
    }

    /// Returns the backing device for `.mmio` or `.virtual_bar`; null
    /// otherwise. Callers that need to discriminate `.mmio` vs
    /// `.virtual_bar` should check `kind` explicitly.
    pub fn deviceRegion(self: *const VmNode) ?*DeviceRegion {
        if (self.kind != .mmio and self.kind != .virtual_bar) return null;
        return @ptrCast(@alignCast(self.kind_ptr));
    }
};

const VmNodeSlab = secure_slab.SecureSlab(VmNode, 256);
var vm_node_slab: VmNodeSlab = undefined;

pub fn initSlabs(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    vm_node_slab = VmNodeSlab.init(data_range, ptrs_range, links_range);
}

/// Allocate a fresh `VmNode` slot and return a SlabRef. The returned
/// ref is self-alive (gen sampled at alloc time; the caller is the
/// sole observer until the ref is stored in `self.nodes[]`), so
/// internal callers under `vmm.lock` may deref via `.ptr` — the node
/// cannot be freed concurrently.
fn allocVmNode() !SlabRef(VmNode) {
    return try vm_node_slab.create();
}

fn freeVmNode(node_ref: SlabRef(VmNode)) void {
    // self-alive: caller proves liveness by holding vmm.lock; the node
    // was just removed from `self.nodes[]` and no other context can
    // observe it after that point.
    // Use the carried gen (from the caller's SlabRef) rather than
    // reading `currentGen()` off the slot — the carried value is what
    // every prior handle to this node has been validated against, so
    // destroy targets that specific generation of the slot.
    vm_node_slab.destroy(node_ref.ptr, @intCast(node_ref.gen)) catch unreachable;
}

fn cmpAddrToNode(ctx_addr: u64, item: SlabRef(VmNode)) std.math.Order {
    // self-alive: sort comparator runs under vmm.lock; every item in
    // the slice is alive for the duration of the search.
    return std.math.order(ctx_addr, item.ptr.start.addr);
}

/// First index `i` into `slice` where `slice[i].start.addr >= addr`.
/// Matches `std.sort.lowerBound` semantics; returns `slice.len` when
/// `addr` is greater than every node's start.
fn lowerBoundIdx(slice: []SlabRef(VmNode), addr: u64) usize {
    return std.sort.lowerBound(SlabRef(VmNode), slice, addr, cmpAddrToNode);
}

pub const ReserveResult = struct {
    vaddr: VAddr,
    node: SlabRef(VmNode),
};

pub const StackResult = struct {
    guard: VAddr,
    base: VAddr,
    top: VAddr,
};

pub const VirtualMemoryManager = struct {
    nodes: [MAX_RESERVATIONS]SlabRef(VmNode),
    count: u32,
    range_start: VAddr,
    range_end: VAddr,
    addr_space_root: PAddr,
    lock: SpinLock,

    pub fn init(start: VAddr, end_vaddr: VAddr, root: PAddr) VirtualMemoryManager {
        return .{
            .nodes = undefined,
            .count = 0,
            .range_start = start,
            .range_end = end_vaddr,
            .addr_space_root = root,
            .lock = .{ .class = "VirtualMemoryManager.lock" },
        };
    }

    /// Active slice view over the sorted reservation array.
    fn slice(self: *VirtualMemoryManager) []SlabRef(VmNode) {
        return self.nodes[0..self.count];
    }

    /// Insert a pre-allocated node at its sorted position. Returns
    /// `error.OutOfMemory` when the per-process reservation cap is full
    /// (`MAX_RESERVATIONS`) — this is the same error shape the tree
    /// insert used to return, so syscall-level callers continue to map
    /// it to `E_NOMEM` without code change.
    fn insertNodeLocked(self: *VirtualMemoryManager, node_ref: SlabRef(VmNode)) !void {
        if (self.count >= MAX_RESERVATIONS) return error.OutOfMemory;
        // self-alive: holding vmm.lock; node_ref was just allocated or
        // is being re-inserted by an internal helper that owns it.
        const idx = lowerBoundIdx(self.slice(), node_ref.ptr.start.addr);
        insertAtIdx(self, idx, node_ref);
    }

    fn insertAtIdx(self: *VirtualMemoryManager, idx: usize, node_ref: SlabRef(VmNode)) void {
        if (idx < self.count) {
            @memmove(self.nodes[idx + 1 .. self.count + 1], self.nodes[idx..self.count]);
        }
        self.nodes[idx] = node_ref;
        self.count += 1;
    }

    fn removeAtIdx(self: *VirtualMemoryManager, idx: usize) void {
        if (idx + 1 < self.count) {
            @memmove(self.nodes[idx .. self.count - 1], self.nodes[idx + 1 .. self.count]);
        }
        self.count -= 1;
    }

    /// Remove the exact node pointer from the array (locates by start
    /// address, verifies pointer identity). Silently no-ops if the node
    /// is not present — preserves the `_ = self.tree.remove(node) catch {}`
    /// "fire and forget" idiom the RB-tree version used in rollback paths.
    fn removeNodeLocked(self: *VirtualMemoryManager, node_ref: SlabRef(VmNode)) void {
        // self-alive: identity compare against a caller-owned ref; the
        // array entry (if present) shares the same slab slot and its
        // gen matches while vmm.lock is held.
        const idx = lowerBoundIdx(self.slice(), node_ref.ptr.start.addr);
        if (idx >= self.count or self.nodes[idx].ptr != node_ref.ptr) return;
        self.removeAtIdx(idx);
    }

    /// Returns the node whose range covers `vaddr`, or null. Each node
    /// occupies a disjoint half-open interval `[start, end)`, so the
    /// only candidate is the greatest-start-≤-vaddr neighbor.
    fn findNodeLocked(self: *VirtualMemoryManager, vaddr: VAddr) ?SlabRef(VmNode) {
        const idx = lowerBoundIdx(self.slice(), vaddr.addr +| 1);
        if (idx == 0) return null;
        const candidate = self.nodes[idx - 1];
        // self-alive: vmm.lock is held — the node is still in the array.
        if (vaddr.addr < candidate.ptr.end()) return candidate;
        return null;
    }

    pub fn allocateAfterCursor(self: *VirtualMemoryManager, size: u64) !VAddr {
        self.lock.lock(@src());
        defer self.lock.unlock();
        const addr = try self.findFreeRange(size);
        if (addr.addr + size > self.range_start.addr) {
            self.range_start = VAddr.fromInt(addr.addr + size);
        }
        return addr;
    }

    pub fn bump(self: *VirtualMemoryManager, past: VAddr) void {
        if (past.addr > self.range_start.addr) {
            self.range_start = past;
        }
    }

    pub fn insertKernelNode(self: *VirtualMemoryManager, start: VAddr, size: u64, rights: VmReservationRights, policy: RestartPolicy) !void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        const node_ref = try allocVmNode();
        // self-alive: freshly allocated; no other observer yet.
        const node = node_ref.ptr;
        // Field-by-field assignment preserves `node._gen_lock`.
        node.start = start;
        node.size = size;
        node.kind = .private;
        node.kind_ptr = null;
        node.rights = rights;
        node.handle = HANDLE_NONE;
        node.restart_policy = policy;

        self.insertNodeLocked(node_ref) catch |e| {
            freeVmNode(node_ref);
            return e;
        };
    }

    pub fn deinit(self: *VirtualMemoryManager) void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const node_ref = self.nodes[i];
            unmapNodePages(node_ref, self.addr_space_root, true);
            freeVmNode(node_ref);
        }
        self.count = 0;
    }

    pub fn findNode(self: *VirtualMemoryManager, vaddr: VAddr) ?SlabRef(VmNode) {
        self.lock.lock(@src());
        defer self.lock.unlock();
        return self.findNodeLocked(vaddr);
    }

    fn findFreeRange(self: *VirtualMemoryManager, size: u64) !VAddr {
        var prev_end: u64 = self.range_start.addr;
        const s = self.slice();

        // Skip nodes entirely below the VMM's current range_start cursor;
        // any gap before `range_start` is off-limits for new reservations.
        var i: usize = lowerBoundIdx(s, self.range_start.addr);
        while (i < s.len) : (i += 1) {
            // self-alive: scanning the array under vmm.lock.
            const node = s[i].ptr;
            if (node.start.addr > prev_end and node.start.addr - prev_end >= size) {
                return VAddr.fromInt(prev_end);
            }
            if (node.end() > prev_end) prev_end = node.end();
        }

        if (self.range_end.addr - prev_end >= size) {
            return VAddr.fromInt(prev_end);
        }
        return error.OutOfMemory;
    }

    pub fn reserve(self: *VirtualMemoryManager, hint: VAddr, size: u64, max_rights: VmReservationRights) !ReserveResult {
        if (!std.mem.isAligned(size, paging.PAGE4K) or size == 0) return error.InvalidSize;

        self.lock.lock(@src());
        defer self.lock.unlock();

        const chosen = blk: {
            // Overflow-checked end of the hinted range. If this wraps,
            // fall straight through to findFreeRange — callers that
            // reach here with a wrapping pair would have been rejected
            // at the syscall layer, but we guard in depth to keep
            // `vmm.reserve` safe against any future in-kernel caller.
            const hint_end = std.math.add(u64, hint.addr, size) catch 0;
            if (hint.addr != 0 and
                hint_end != 0 and
                std.mem.isAligned(hint.addr, paging.PAGE4K) and
                hint.addr >= self.range_start.addr and
                hint_end <= self.range_end.addr)
            {
                const s = self.slice();
                const upper_idx = lowerBoundIdx(s, hint.addr);

                // lower: greatest-start-strictly-less-than-hint neighbor
                // self-alive: array walk under vmm.lock.
                const hint_free = if (upper_idx == 0)
                    true
                else
                    hint.addr >= s[upper_idx - 1].ptr.end();

                // upper: first node with start >= hint. If it starts
                // inside [hint, hint_end), the hinted range is not clear.
                // self-alive: array walk under vmm.lock.
                const range_clear = if (upper_idx >= s.len)
                    true
                else
                    s[upper_idx].ptr.start.addr >= hint_end;

                if (hint_free and range_clear) break :blk hint;
            }
            break :blk try self.findFreeRange(size);
        };

        const node_ref = try allocVmNode();
        // self-alive: freshly allocated; no other observer until insert.
        node_ref.ptr.init(
            chosen,
            size,
            .private,
            null,
            .{
                .read = max_rights.read,
                .write = max_rights.write,
                .execute = max_rights.execute,
            },
            HANDLE_NONE,
            .free,
        );

        self.insertNodeLocked(node_ref) catch |e| {
            freeVmNode(node_ref);
            return e;
        };

        return .{ .vaddr = chosen, .node = node_ref };
    }

    pub fn reserveStack(self: *VirtualMemoryManager, num_pages: u32) !StackResult {
        const usable_size = @as(u64, num_pages) * paging.PAGE4K;
        const total = usable_size + 2 * paging.PAGE4K;

        self.lock.lock(@src());
        defer self.lock.unlock();

        const base_addr = try self.findFreeRange(total);
        const usable_start = base_addr.addr + paging.PAGE4K;
        const overflow_start = usable_start + usable_size;

        const underflow_ref = try allocVmNode();
        // self-alive: freshly allocated; no other observer yet.
        underflow_ref.ptr.init(base_addr, paging.PAGE4K, .private, null, .{}, HANDLE_NONE, .free);

        self.insertNodeLocked(underflow_ref) catch |e| {
            freeVmNode(underflow_ref);
            return e;
        };

        const stack_ref = try allocVmNode();
        // self-alive: freshly allocated.
        stack_ref.ptr.init(
            VAddr.fromInt(usable_start),
            usable_size,
            .private,
            null,
            .{ .read = true, .write = true },
            HANDLE_NONE,
            .free,
        );

        self.insertNodeLocked(stack_ref) catch |e| {
            self.removeNodeLocked(underflow_ref);
            freeVmNode(underflow_ref);
            freeVmNode(stack_ref);
            return e;
        };

        const overflow_ref = try allocVmNode();
        // self-alive: freshly allocated.
        overflow_ref.ptr.init(
            VAddr.fromInt(overflow_start),
            paging.PAGE4K,
            .private,
            null,
            .{},
            HANDLE_NONE,
            .free,
        );

        self.insertNodeLocked(overflow_ref) catch |e| {
            unmapNodePages(stack_ref, self.addr_space_root, true);
            self.removeNodeLocked(stack_ref);
            self.removeNodeLocked(underflow_ref);
            freeVmNode(overflow_ref);
            freeVmNode(stack_ref);
            freeVmNode(underflow_ref);
            return e;
        };

        const pmm_mgr = &pmm.global_pmm.?;
        const top_page_va = VAddr.fromInt(overflow_start - paging.PAGE4K);
        const top_page = pmm_mgr.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
        const top_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(top_page)), null);
        const stack_perms = rightsToMemPerms(.{ .read = true, .write = true }, .user);
        arch.paging.mapPage(self.addr_space_root, top_phys, top_page_va, stack_perms) catch {
            pmm_mgr.destroy(top_page);
            return error.OutOfMemory;
        };

        return .{
            .guard = base_addr,
            .base = VAddr.fromInt(usable_start),
            .top = VAddr.fromInt(overflow_start),
        };
    }

    pub fn reclaimStack(self: *VirtualMemoryManager, stack: zag.memory.stack.Stack) void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        if (self.findNodeLocked(stack.guard)) |underflow_ref| {
            self.removeNodeLocked(underflow_ref);
            freeVmNode(underflow_ref);
        }
        if (self.findNodeLocked(stack.base)) |stack_ref| {
            unmapNodePages(stack_ref, self.addr_space_root, true);
            self.removeNodeLocked(stack_ref);
            freeVmNode(stack_ref);
        }
        if (self.findNodeLocked(stack.top)) |overflow_ref| {
            self.removeNodeLocked(overflow_ref);
            freeVmNode(overflow_ref);
        }
    }

    pub fn demandPage(self: *VirtualMemoryManager, fault_vaddr: VAddr, is_write: bool, is_exec: bool) !void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        const node_ref = self.findNodeLocked(fault_vaddr) orelse return error.NoMapping;
        // self-alive: node is in the array under vmm.lock.
        const node = node_ref.ptr;

        // Rights check lives *above* the already-resolved fast path on
        // purpose. Callers pre-fault with (is_write, is_exec) reflecting
        // the access the kernel is about to make on behalf of the user
        // (e.g. vmRecv pre-faults with is_write=true because it's going
        // to physmap-write the exit message into the buffer). For
        // already-backed SHM nodes the fast path would otherwise return
        // ok without ever comparing those intent bits to node.rights,
        // letting a process with R/O SHM use any "pre-fault + physmap
        // write" syscall path to write through its own R/O mapping.
        if (is_write and !node.rights.write) return error.PermissionDenied;
        if (is_exec and !node.rights.execute) return error.PermissionDenied;
        if (!is_write and !is_exec and !node.rights.read) return error.PermissionDenied;

        // Fast path: if the page is already backed (e.g., SHM/MMIO mapping,
        // a previously faulted-in private page), this is a no-op. Check this
        // before rejecting non-private nodes so callers can blindly pre-fault
        // every page in an arbitrary user range (e.g., the proc_create ELF
        // pre-fault loop that handles both demand-paged private sources and
        // SHM-backed ELF sources).
        const page_base = VAddr.fromInt(std.mem.alignBackward(u64, fault_vaddr.addr, paging.PAGE4K));
        if (arch.paging.resolveVaddr(self.addr_space_root, page_base) != null) return;

        if (node.kind != .private) return error.NotDemandPageable;

        const pmm_mgr = &pmm.global_pmm.?;
        const page = pmm_mgr.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;

        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        const perms = rightsToMemPerms(node.rights, .user);

        arch.paging.mapPage(self.addr_space_root, phys, page_base, perms) catch {
            pmm_mgr.destroy(page);
            return error.OutOfMemory;
        };
    }

    pub fn memPerms(
        self: *VirtualMemoryManager,
        vm_handle: u64,
        original_start: VAddr,
        original_size: u64,
        offset: u64,
        size: u64,
        new_rights: VmReservationRights,
    ) !void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        const range_start = VAddr.fromInt(original_start.addr + offset);
        const range_end_addr = range_start.addr + size;
        _ = original_size;
        _ = vm_handle;

        try self.splitAtLocked(range_start);
        try self.splitAtLocked(VAddr.fromInt(range_end_addr));

        // Reject if range contains non-private nodes (SHM/MMIO).
        const s = self.slice();
        const lo = lowerBoundIdx(s, range_start.addr);
        const hi = lowerBoundIdx(s, range_end_addr);
        var i: usize = lo;
        while (i < hi) : (i += 1) {
            // self-alive: array walk under vmm.lock.
            if (s[i].ptr.kind != .private) return error.NonPrivateRange;
        }

        i = lo;
        while (i < hi) : (i += 1) {
            const node_ref = s[i];
            // self-alive: array walk under vmm.lock.
            const node = node_ref.ptr;
            if (node.kind != .private) continue;
            node.rights = new_rights;
            updateCommittedPages(node_ref, self.addr_space_root, new_rights, .user);
        }

        self.mergeRangeLocked(range_start, VAddr.fromInt(range_end_addr));
    }

    pub fn memShmMap(
        self: *VirtualMemoryManager,
        shm_handle: u64,
        vm_handle: u64,
        original_start: VAddr,
        original_size: u64,
        offset: u64,
        shm_ref: SlabRef(SharedMemory),
        rights: VmReservationRights,
    ) !void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        // self-alive: caller holds shm._gen_lock across this call (see
        // sysMemShmMap); the SHM object cannot be freed beneath us.
        const shm = shm_ref.ptr;

        const range_start = VAddr.fromInt(original_start.addr + offset);
        const range_size = shm.size();
        const range_end_addr = range_start.addr + range_size;
        _ = vm_handle;

        if (self.hasDuplicateShmLocked(original_start, original_size, shm))
            return error.DuplicateMapping;

        try self.splitAtLocked(range_start);
        try self.splitAtLocked(VAddr.fromInt(range_end_addr));

        if (self.hasCommittedPagesLocked(range_start, range_end_addr))
            return error.CommittedPages;

        try self.removeRangeLocked(range_start, range_end_addr);

        const map_ref = try allocVmNode();
        // self-alive: freshly allocated.
        map_ref.ptr.init(
            range_start,
            range_size,
            .shared_memory,
            shm,
            .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            shm_handle,
            .free,
        );

        self.insertNodeLocked(map_ref) catch |e| {
            freeVmNode(map_ref);
            return e;
        };

        const perms = rightsToMemPerms(
            .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            .user,
        );

        // §3.2: if the SHM handle lacks `read`, leave the pages non-present
        // so any access (read or write) traps into the page fault handler,
        // which looks up the VMM node (kind = .shared_memory) and reports
        // invalid_read / invalid_write based on the access type.  On x86
        // there is no "no-read" PTE bit, so unmapping is the only way to
        // make reads fault on SHM regions.
        if (rights.read) {
            var i: usize = 0;
            while (i < shm.num_pages) : (i += 1) {
                const page_virt = VAddr.fromInt(range_start.addr + @as(u64, i) * paging.PAGE4K);
                arch.paging.mapPage(self.addr_space_root, shm.pageAddr(i), page_virt, perms) catch {
                    var j: usize = 0;
                    while (j < i) {
                        _ = arch.paging.unmapPage(self.addr_space_root, VAddr.fromInt(range_start.addr + @as(u64, j) * paging.PAGE4K));
                        j += 1;
                    }
                    self.removeNodeLocked(map_ref);
                    freeVmNode(map_ref);
                    return error.OutOfMemory;
                };
            }
        }
    }

    pub fn memUnmap(
        self: *VirtualMemoryManager,
        vm_handle: u64,
        original_start: VAddr,
        original_size: u64,
        offset: u64,
        size: u64,
        max_rights: VmReservationRights,
    ) !void {
        self.lock.lock(@src());
        defer self.lock.unlock();
        _ = vm_handle;
        _ = original_size;

        const range_start = VAddr.fromInt(original_start.addr + offset);
        const range_end_addr = range_start.addr + size;

        // §2.3.7/§2.3.47: SHM, MMIO, and virtual BAR nodes must be fully
        // contained — partial overlap returns E_INVAL. Check the boundary
        // nodes BEFORE splitting (splitAtLocked would split non-private
        // nodes, corrupting them).
        if (self.findNodeLocked(range_start)) |node_ref| {
            // self-alive: under vmm.lock.
            const node = node_ref.ptr;
            if (node.kind != .private and node.start.addr < range_start.addr)
                return error.PartialOverlap;
        }
        if (self.findNodeLocked(VAddr.fromInt(range_end_addr -| 1))) |node_ref| {
            // self-alive: under vmm.lock.
            const node = node_ref.ptr;
            if (node.kind != .private and node.start.addr + node.size > range_end_addr)
                return error.PartialOverlap;
        }

        // Split private nodes at range boundaries.
        try self.splitAtLocked(range_start);
        try self.splitAtLocked(VAddr.fromInt(range_end_addr));

        // UNMAP PASS: drop non-private nodes into `to_replace` so we can
        // swap them for private placeholders after the iteration — we
        // avoid mutating the array while iterating over it.
        var to_replace: [128]SlabRef(VmNode) = undefined;
        var replace_count: usize = 0;

        {
            const s = self.slice();
            const lo = lowerBoundIdx(s, range_start.addr);
            const hi = lowerBoundIdx(s, range_end_addr);
            var i: usize = lo;
            while (i < hi) : (i += 1) {
                const node_ref = s[i];
                // self-alive: iterating the array under vmm.lock.
                const node = node_ref.ptr;
                const unmap_rights: VmReservationRights = .{
                    .read = max_rights.read,
                    .write = max_rights.write,
                    .execute = max_rights.execute,
                };
                switch (node.kind) {
                    .private => {
                        unmapNodePages(node_ref, self.addr_space_root, true);
                        node.rights = unmap_rights;
                    },
                    .shared_memory, .mmio, .virtual_bar => {
                        if (node.kind != .virtual_bar) {
                            unmapNodePages(node_ref, self.addr_space_root, false);
                        }
                        if (replace_count < to_replace.len) {
                            to_replace[replace_count] = node_ref;
                            replace_count += 1;
                        }
                    },
                }
            }
        }

        // Replace non-private nodes with private nodes.
        for (to_replace[0..replace_count]) |node_ref| {
            // self-alive: under vmm.lock; we just picked this node up
            // from the array in the pass above.
            const node = node_ref.ptr;
            const old_start = node.start;
            const old_size = node.size;
            const old_handle = node.handle;
            self.removeNodeLocked(node_ref);
            freeVmNode(node_ref);

            const replacement_ref = allocVmNode() catch continue;
            // self-alive: freshly allocated.
            replacement_ref.ptr.init(
                old_start,
                old_size,
                .private,
                null,
                .{
                    .read = max_rights.read,
                    .write = max_rights.write,
                    .execute = max_rights.execute,
                },
                old_handle,
                .free,
            );
            self.insertNodeLocked(replacement_ref) catch freeVmNode(replacement_ref);
        }

        self.mergeRangeLocked(range_start, VAddr.fromInt(range_end_addr));
    }

    pub fn memMmioMap(
        self: *VirtualMemoryManager,
        device_handle: u64,
        vm_handle: u64,
        original_start: VAddr,
        original_size: u64,
        offset: u64,
        device_ref: SlabRef(DeviceRegion),
        write_combining: bool,
        rights: VmReservationRights,
    ) !void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        // self-alive: caller (sysMemMmioMap) holds device._gen_lock across
        // this call, so the DeviceRegion cannot be freed beneath us.
        const device = device_ref.ptr;

        const range_start = VAddr.fromInt(original_start.addr + offset);
        const range_size = device.access.mmio.size;
        const range_end_addr = range_start.addr + range_size;
        _ = vm_handle;

        if (self.hasDuplicateMmioLocked(original_start, original_size, device))
            return error.DuplicateMapping;

        try self.splitAtLocked(range_start);
        try self.splitAtLocked(VAddr.fromInt(range_end_addr));

        if (self.hasCommittedPagesLocked(range_start, range_end_addr))
            return error.CommittedPages;

        try self.removeRangeLocked(range_start, range_end_addr);

        const map_ref = try allocVmNode();
        // self-alive: freshly allocated.
        map_ref.ptr.init(
            range_start,
            range_size,
            .mmio,
            device,
            .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            device_handle,
            .free,
        );

        self.insertNodeLocked(map_ref) catch |e| {
            freeVmNode(map_ref);
            return e;
        };

        const perms = MemoryPerms{
            .write_perm = if (rights.write) .write else .no_write,
            .execute_perm = if (rights.execute) .execute else .no_execute,
            .cache_perm = if (write_combining) .write_combining else .not_cacheable,
            .global_perm = .not_global,
            .privilege_perm = .user,
        };

        // §3.2: leave MMIO pages non-present when the reservation lacks
        // `read`, so any access traps into the page fault handler and is
        // resolved against the VMM node's rights (.mmio kind) to report
        // invalid_read / invalid_write / invalid_execute.
        if (rights.read) {
            var mapped: u64 = 0;
            while (mapped < range_size) {
                const page_phys = PAddr.fromInt(device.access.mmio.phys_base.addr + mapped);
                const page_virt = VAddr.fromInt(range_start.addr + mapped);
                arch.paging.mapPage(self.addr_space_root, page_phys, page_virt, perms) catch {
                    var undo: u64 = 0;
                    while (undo < mapped) {
                        _ = arch.paging.unmapPage(self.addr_space_root, VAddr.fromInt(range_start.addr + undo));
                        undo += paging.PAGE4K;
                    }
                    self.removeNodeLocked(map_ref);
                    freeVmNode(map_ref);
                    return error.OutOfMemory;
                };
                mapped += paging.PAGE4K;
            }
        }
    }

    pub fn memVirtualBarMap(
        self: *VirtualMemoryManager,
        device_handle: u64,
        vm_handle: u64,
        original_start: VAddr,
        original_size: u64,
        offset: u64,
        device_ref: SlabRef(DeviceRegion),
        rights: VmReservationRights,
    ) !void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        // self-alive: caller (sysMemMmioMap) holds device._gen_lock across
        // this call.
        const device = device_ref.ptr;

        const range_start = VAddr.fromInt(original_start.addr + offset);
        const range_size = std.mem.alignForward(u64, device.access.port_io.port_count, paging.PAGE4K);
        const range_end_addr = range_start.addr + range_size;
        _ = vm_handle;

        if (self.hasDuplicateVirtualBarLocked(original_start, original_size, device))
            return error.DuplicateMapping;

        try self.splitAtLocked(range_start);
        try self.splitAtLocked(VAddr.fromInt(range_end_addr));

        if (self.hasCommittedPagesLocked(range_start, range_end_addr))
            return error.CommittedPages;

        try self.removeRangeLocked(range_start, range_end_addr);

        const map_ref = try allocVmNode();
        // self-alive: freshly allocated.
        map_ref.ptr.init(
            range_start,
            range_size,
            .virtual_bar,
            device,
            .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            device_handle,
            .free,
        );

        self.insertNodeLocked(map_ref) catch |e| {
            freeVmNode(map_ref);
            return e;
        };

        // No page mapping — PTEs are left absent intentionally so that
        // every access traps into the page fault handler, which decodes
        // the faulting instruction and performs the port I/O.
    }

    pub fn revokeReservation(
        self: *VirtualMemoryManager,
        original_start: VAddr,
        original_size: u64,
    ) !void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        const range_end_addr = original_start.addr + original_size;

        // Iterate from the end so in-place removals don't invalidate
        // earlier indices we haven't processed yet.
        const s = self.slice();
        const lo = lowerBoundIdx(s, original_start.addr);
        const hi = lowerBoundIdx(s, range_end_addr);
        var i: usize = hi;
        while (i > lo) {
            i -= 1;
            const node_ref = self.nodes[i];
            // self-alive: under vmm.lock.
            const free_phys = node_ref.ptr.kind == .private;
            unmapNodePages(node_ref, self.addr_space_root, free_phys);
            self.removeAtIdx(i);
            freeVmNode(node_ref);
        }
    }

    pub const ReservationInfo = struct {
        start: u64,
        end: u64,
        rights: VmReservationRights,
    };

    pub fn revokeShmHandle(self: *VirtualMemoryManager, shm: *SharedMemory, reservations: []const ReservationInfo) void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const node_ref = self.nodes[i];
            // self-alive: under vmm.lock.
            const node = node_ref.ptr;
            if (node.kind != .shared_memory) continue;
            if (node.sharedMemory() != shm) continue;
            unmapNodePages(node_ref, self.addr_space_root, false);
            node.kind = .private;
            node.rights = findContainingRights(reservations, node.start.addr);
            node.handle = HANDLE_NONE;
            node.restart_policy = .free;
        }
    }

    pub fn revokeMmioHandle(self: *VirtualMemoryManager, device: *DeviceRegion, reservations: []const ReservationInfo) void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const node_ref = self.nodes[i];
            // self-alive: under vmm.lock.
            const node = node_ref.ptr;
            const is_mmio = node.kind == .mmio and node.deviceRegion() == device;
            const is_vbar = node.kind == .virtual_bar and node.deviceRegion() == device;
            if (!is_mmio and !is_vbar) continue;
            if (is_mmio) unmapNodePages(node_ref, self.addr_space_root, false);
            node.kind = .private;
            node.rights = findContainingRights(reservations, node.start.addr);
            node.handle = HANDLE_NONE;
            node.restart_policy = .free;
        }
    }

    pub fn resetForRestart(self: *VirtualMemoryManager) void {
        self.lock.lock(@src());
        defer self.lock.unlock();

        // Walk from the end so removals can't shift nodes we haven't
        // visited yet. `.free` victims get removed outright; `.decommit`
        // just drops their backing pages; `.preserve` is a no-op.
        var i: usize = self.count;
        while (i > 0) {
            i -= 1;
            const node_ref = self.nodes[i];
            // self-alive: under vmm.lock.
            const node = node_ref.ptr;
            switch (node.restart_policy) {
                .free => {
                    const free_phys = node.kind == .private;
                    unmapNodePages(node_ref, self.addr_space_root, free_phys);
                    self.removeAtIdx(i);
                    freeVmNode(node_ref);
                },
                .decommit => {
                    unmapNodePages(node_ref, self.addr_space_root, true);
                },
                .preserve => {},
            }
        }
    }

    // ── Internal helpers (locked) ──────────────────────────────────────

    fn splitAtLocked(self: *VirtualMemoryManager, split_vaddr: VAddr) !void {
        const node_ref = self.findNodeLocked(split_vaddr) orelse return;
        // self-alive: under vmm.lock.
        const node = node_ref.ptr;
        if (node.start.addr == split_vaddr.addr) return;

        const right_ref = try allocVmNode();
        // self-alive: freshly allocated.
        const right = right_ref.ptr;
        // Field-by-field write preserves `right._gen_lock`.
        right.start = split_vaddr;
        right.size = node.end() - split_vaddr.addr;
        right.kind = node.kind;
        right.kind_ptr = node.kind_ptr;
        right.rights = node.rights;
        right.handle = node.handle;
        right.restart_policy = node.restart_policy;
        node.size = split_vaddr.addr - node.start.addr;

        self.insertNodeLocked(right_ref) catch |e| {
            node.size = right.end() - node.start.addr;
            freeVmNode(right_ref);
            return e;
        };
    }

    fn mergeRangeLocked(self: *VirtualMemoryManager, range_start: VAddr, range_end: VAddr) void {
        // Right-edge merge: the node starting at range_end may merge
        // with the node immediately before it.
        self.tryMergeAt(range_end);

        // Left-to-right sweep through the range, merging each mergeable
        // successor into its predecessor. Walk the array index-by-index
        // so removals can't desync our cursor.
        var idx = lowerBoundIdx(self.slice(), range_start.addr);
        while (idx + 1 < self.count) {
            // self-alive: under vmm.lock.
            const node = self.nodes[idx].ptr;
            if (node.start.addr >= range_end.addr) break;
            const next_ref = self.nodes[idx + 1];
            // self-alive: under vmm.lock.
            const next = next_ref.ptr;
            if (next.start.addr >= range_end.addr) break;
            if (canMerge(node, next)) {
                node.size += next.size;
                self.removeAtIdx(idx + 1);
                freeVmNode(next_ref);
                // Stay at `idx` — another successor may now be mergeable too.
                continue;
            }
            idx += 1;
        }

        // Left-edge merge: the node that ends at range_start may merge
        // with the first node of the range (which is now `idx` in the
        // post-sweep array).
        self.tryMergeAt(range_start);
    }

    fn tryMergeAt(self: *VirtualMemoryManager, vaddr: VAddr) void {
        const idx = lowerBoundIdx(self.slice(), vaddr.addr);
        if (idx == 0 or idx >= self.count) return;
        const node_ref = self.nodes[idx];
        // self-alive: under vmm.lock.
        const node = node_ref.ptr;
        if (node.start.addr != vaddr.addr) return;
        // self-alive: under vmm.lock.
        const prev = self.nodes[idx - 1].ptr;
        if (!canMerge(prev, node)) return;
        prev.size += node.size;
        self.removeAtIdx(idx);
        freeVmNode(node_ref);
    }

    fn removeRangeLocked(self: *VirtualMemoryManager, range_start: VAddr, range_end_addr: u64) !void {
        kprof.enter(.vmm_remove_range);
        defer kprof.exit(.vmm_remove_range);

        // Walk backward to keep indices stable during in-place removal.
        const lo = lowerBoundIdx(self.slice(), range_start.addr);
        const hi = lowerBoundIdx(self.slice(), range_end_addr);
        var i: usize = hi;
        while (i > lo) {
            i -= 1;
            const node_ref = self.nodes[i];
            self.removeAtIdx(i);
            freeVmNode(node_ref);
        }
    }

    fn hasDuplicateShmLocked(self: *VirtualMemoryManager, res_start: VAddr, res_size: u64, shm: *SharedMemory) bool {
        const s = self.slice();
        const lo = lowerBoundIdx(s, res_start.addr);
        const hi = lowerBoundIdx(s, res_start.addr + res_size);
        var i: usize = lo;
        while (i < hi) : (i += 1) {
            // self-alive: array walk under vmm.lock.
            const node = s[i].ptr;
            if (node.kind == .shared_memory and node.sharedMemory() == shm) return true;
        }
        return false;
    }

    fn hasDuplicateMmioLocked(self: *VirtualMemoryManager, res_start: VAddr, res_size: u64, device: *DeviceRegion) bool {
        const s = self.slice();
        const lo = lowerBoundIdx(s, res_start.addr);
        const hi = lowerBoundIdx(s, res_start.addr + res_size);
        var i: usize = lo;
        while (i < hi) : (i += 1) {
            // self-alive: array walk under vmm.lock.
            const node = s[i].ptr;
            if (node.kind == .mmio and node.deviceRegion() == device) return true;
        }
        return false;
    }

    fn hasDuplicateVirtualBarLocked(self: *VirtualMemoryManager, res_start: VAddr, res_size: u64, device: *DeviceRegion) bool {
        const s = self.slice();
        const lo = lowerBoundIdx(s, res_start.addr);
        const hi = lowerBoundIdx(s, res_start.addr + res_size);
        var i: usize = lo;
        while (i < hi) : (i += 1) {
            // self-alive: array walk under vmm.lock.
            const node = s[i].ptr;
            if (node.kind == .virtual_bar and node.deviceRegion() == device) return true;
        }
        return false;
    }

    fn hasCommittedPagesLocked(self: *VirtualMemoryManager, range_start: VAddr, range_end_addr: u64) bool {
        const s = self.slice();
        const lo = lowerBoundIdx(s, range_start.addr);
        const hi = lowerBoundIdx(s, range_end_addr);
        var i: usize = lo;
        while (i < hi) : (i += 1) {
            // self-alive: array walk under vmm.lock.
            if (arch.paging.resolveVaddr(self.addr_space_root, s[i].ptr.start) != null) return true;
        }
        return false;
    }
};

fn findContainingRights(reservations: []const VirtualMemoryManager.ReservationInfo, addr: u64) VmReservationRights {
    for (reservations) |res| {
        if (addr >= res.start and addr < res.end) return res.rights;
    }
    return .{ .read = true, .write = true, .execute = true };
}

fn canMerge(a: *VmNode, b: *VmNode) bool {
    if (a.kind != .private or b.kind != .private) return false;
    if (a.handle != b.handle) return false;
    if (a.restart_policy != b.restart_policy) return false;
    if (a.rights.read != b.rights.read) return false;
    if (a.rights.write != b.rights.write) return false;
    if (a.rights.execute != b.rights.execute) return false;
    return a.end() == b.start.addr;
}

fn unmapNodePages(node_ref: SlabRef(VmNode), addr_space_root: PAddr, free_phys: bool) void {
    // self-alive: callers hold vmm.lock; the node is stored in
    // self.nodes[] or was just removed by the same critical section.
    const node = node_ref.ptr;

    // virtual_bar nodes have no mapped pages — PTEs are intentionally absent
    if (node.kind == .virtual_bar) return;

    const pmm_mgr = &pmm.global_pmm.?;
    var page_addr = node.start.addr;
    while (page_addr < node.end()) {
        if (arch.paging.unmapPage(addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
            if (free_phys and node.kind == .private) {
                const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
                pmm_mgr.destroy(page);
            }
        }
        page_addr += paging.PAGE4K;
    }
}

fn updateCommittedPages(
    node_ref: SlabRef(VmNode),
    addr_space_root: PAddr,
    rights: VmReservationRights,
    privilege: PrivilegePerm,
) void {
    // self-alive: caller (memPerms) holds vmm.lock; node is live in the
    // array.
    const node = node_ref.ptr;

    const is_decommit = !rights.read and !rights.write and !rights.execute;

    if (is_decommit) {
        const pmm_mgr = &pmm.global_pmm.?;
        var page_addr = node.start.addr;
        while (page_addr < node.end()) {
            if (arch.paging.unmapPage(addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
                if (node.kind == .private) {
                    const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
                    pmm_mgr.destroy(page);
                }
            }
            page_addr += paging.PAGE4K;
        }
        return;
    }

    const perms = rightsToMemPerms(rights, privilege);
    var page_addr = node.start.addr;
    while (page_addr < node.end()) {
        const vaddr = VAddr.fromInt(page_addr);
        if (arch.paging.resolveVaddr(addr_space_root, vaddr) != null) {
            arch.paging.updatePagePerms(addr_space_root, vaddr, perms);
        }
        page_addr += paging.PAGE4K;
    }
}

fn rightsToMemPerms(rights: VmReservationRights, privilege: PrivilegePerm) MemoryPerms {
    return .{
        .write_perm = if (rights.write) .write else .no_write,
        .execute_perm = if (rights.execute) .execute else .no_execute,
        .cache_perm = .write_back,
        .global_perm = if (privilege == .kernel) .global else .not_global,
        .privilege_perm = privilege,
    };
}
