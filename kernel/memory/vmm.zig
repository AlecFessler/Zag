const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const secure_slab = zag.memory.allocators.secure_slab;

const GenLock = secure_slab.GenLock;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const SlabRef = secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;
const VarCaps = zag.capdom.var_range.VarCaps;

/// Per-VMM reservation cap. Reservations live in a sorted inline
/// `[MAX_RESERVATIONS]SlabRef(VmNode)` array — lookups are
/// `std.sort.lowerBound` (O(log N) over cache-friendly contiguous
/// memory), insert/remove are `@memmove` of the tail (O(N) but N is
/// bounded and the compiler vectorizes the shift). VARs replaced the
/// SHM/MMIO/virtual-BAR variants in spec v3, so every node here is a
/// private demand-paged region or stack guard.
pub const MAX_RESERVATIONS: usize = 256;

/// Effective rwx for a private VMM node. Only the `r`/`w`/`x` bits of
/// `VarCaps` are interpreted here — the rest of the VarCaps fields
/// (move/copy/mmio/dma/restart_policy) have no meaning for an internal
/// VMM node and are kept zero.
pub const VmNode = extern struct {
    _gen_lock: GenLock = .{},
    start: VAddr,
    size: u64,
    rights: VarCaps,
    _pad: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },

    pub fn end(self: *const VmNode) u64 {
        return self.start.addr + self.size;
    }

    /// Populate every non-`_gen_lock` field of a freshly allocated node.
    /// Use this instead of `node.* = .{...}` — a whole-struct assignment
    /// would clobber the gen-lock word that the allocator just set.
    pub fn init(self: *VmNode, start: VAddr, size: u64, rights: VarCaps) void {
        self.start = start;
        self.size = size;
        self.rights = rights;
        self._pad = .{ 0, 0, 0, 0, 0, 0 };
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
    /// `error.OutOfMemory` when the per-VMM reservation cap is full
    /// (`MAX_RESERVATIONS`) — syscall-level callers map this to
    /// `E_NOMEM`.
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
    /// is not present — preserves the "fire and forget" idiom rollback
    /// paths rely on.
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
        underflow_ref.ptr.init(base_addr, paging.PAGE4K, .{});

        self.insertNodeLocked(underflow_ref) catch |e| {
            freeVmNode(underflow_ref);
            return e;
        };

        const stack_ref = try allocVmNode();
        // self-alive: freshly allocated.
        stack_ref.ptr.init(
            VAddr.fromInt(usable_start),
            usable_size,
            .{ .r = true, .w = true },
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
            .{},
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
        const stack_perms = MemoryPerms{ .read = true, .write = true };
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

        // Rights check lives above the already-resolved fast path on
        // purpose. Callers pre-fault with (is_write, is_exec) reflecting
        // the access the kernel is about to make on behalf of the user.
        // Without this gate, an already-backed node would satisfy any
        // pre-fault syscall path without comparing intent to node.rights.
        if (is_write and !node.rights.w) return error.PermissionDenied;
        if (is_exec and !node.rights.x) return error.PermissionDenied;
        if (!is_write and !is_exec and !node.rights.r) return error.PermissionDenied;

        // Fast path: page already backed (e.g. previously faulted-in).
        const page_base = VAddr.fromInt(std.mem.alignBackward(u64, fault_vaddr.addr, paging.PAGE4K));
        if (arch.paging.resolveVaddr(self.addr_space_root, page_base) != null) return;

        const pmm_mgr = &pmm.global_pmm.?;
        const page = pmm_mgr.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;

        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        const perms = rwxToMemPerms(node.rights);

        arch.paging.mapPage(self.addr_space_root, phys, page_base, perms) catch {
            pmm_mgr.destroy(page);
            return error.OutOfMemory;
        };
    }
};

fn unmapNodePages(node_ref: SlabRef(VmNode), addr_space_root: PAddr, free_phys: bool) void {
    // self-alive: callers hold vmm.lock; the node is stored in
    // self.nodes[] or was just removed by the same critical section.
    const node = node_ref.ptr;

    const pmm_mgr = &pmm.global_pmm.?;
    var page_addr = node.start.addr;
    while (page_addr < node.end()) {
        if (arch.paging.unmapPage(addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
            if (free_phys) {
                const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
                pmm_mgr.destroy(page);
            }
        }
        page_addr += paging.PAGE4K;
    }
}

fn rwxToMemPerms(rights: VarCaps) MemoryPerms {
    return .{
        .read = rights.r,
        .write = rights.w,
        .exec = rights.x,
    };
}
