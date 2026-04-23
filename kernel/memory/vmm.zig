const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const kprof = zag.kprof.trace_id;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const slab_mod = zag.memory.allocators.slab;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PrivilegePerm = zag.perms.privilege.PrivilegePerm;
const SharedMemory = zag.memory.shared.SharedMemory;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;
const VmReservationRights = zag.perms.permissions.VmReservationRights;

pub const HANDLE_NONE: u64 = std.math.maxInt(u64);

/// Per-process reservation cap. Reservations live in a sorted inline
/// `[MAX_RESERVATIONS]*VmNode` array inside every process's VMM —
/// lookups are `std.sort.lowerBound` (O(log N) with cache-friendly
/// contiguous memory), insert/remove are `@memmove` of the tail (O(N)
/// but N ≤ 256 and the compiler vectorizes the shift). Every reservation
/// type stacks the same way: private ranges, SHM maps, MMIO maps,
/// virtual-BAR maps, kernel reservations, plus the underflow/overflow
/// guards around each user stack.
pub const MAX_RESERVATIONS: usize = 256;

pub const RestartPolicy = enum {
    free,
    decommit,
    preserve,
};

pub const VmNode = struct {
    start: VAddr,
    size: u64,
    kind: union(enum) {
        private: void,
        shared_memory: *SharedMemory,
        mmio: *DeviceRegion,
        virtual_bar: *DeviceRegion,
    },
    rights: VmReservationRights,
    handle: u64,
    restart_policy: RestartPolicy,

    pub fn end(self: *const VmNode) u64 {
        return self.start.addr + self.size;
    }
};

const VmNodeSlab = slab_mod.SlabAllocator(VmNode, false, 0, 64, true);
var vm_node_slab: VmNodeSlab = undefined;

pub fn initSlabs(node_backing: std.mem.Allocator) !void {
    vm_node_slab = try VmNodeSlab.init(node_backing);
}

fn allocVmNode() !*VmNode {
    return vm_node_slab.allocator().create(VmNode);
}

fn freeVmNode(node: *VmNode) void {
    vm_node_slab.allocator().destroy(node);
}

fn cmpAddrToNode(ctx_addr: u64, item: *VmNode) std.math.Order {
    return std.math.order(ctx_addr, item.start.addr);
}

/// First index `i` into `slice` where `slice[i].start.addr >= addr`.
/// Matches `std.sort.lowerBound` semantics; returns `slice.len` when
/// `addr` is greater than every node's start.
fn lowerBoundIdx(slice: []*VmNode, addr: u64) usize {
    return std.sort.lowerBound(*VmNode, slice, addr, cmpAddrToNode);
}

pub const ReserveResult = struct {
    vaddr: VAddr,
    node: *VmNode,
};

pub const StackResult = struct {
    guard: VAddr,
    base: VAddr,
    top: VAddr,
};

pub const VirtualMemoryManager = struct {
    nodes: [MAX_RESERVATIONS]*VmNode,
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
            .lock = .{},
        };
    }

    /// Active slice view over the sorted reservation array.
    fn slice(self: *VirtualMemoryManager) []*VmNode {
        return self.nodes[0..self.count];
    }

    /// Insert a pre-allocated node at its sorted position. Returns
    /// `error.OutOfMemory` when the per-process reservation cap is full
    /// (`MAX_RESERVATIONS`) — this is the same error shape the tree
    /// insert used to return, so syscall-level callers continue to map
    /// it to `E_NOMEM` without code change.
    fn insertNodeLocked(self: *VirtualMemoryManager, node: *VmNode) !void {
        if (self.count >= MAX_RESERVATIONS) return error.OutOfMemory;
        const idx = lowerBoundIdx(self.slice(), node.start.addr);
        insertAtIdx(self, idx, node);
    }

    fn insertAtIdx(self: *VirtualMemoryManager, idx: usize, node: *VmNode) void {
        if (idx < self.count) {
            @memmove(self.nodes[idx + 1 .. self.count + 1], self.nodes[idx..self.count]);
        }
        self.nodes[idx] = node;
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
    fn removeNodeLocked(self: *VirtualMemoryManager, node: *VmNode) void {
        const idx = lowerBoundIdx(self.slice(), node.start.addr);
        if (idx >= self.count or self.nodes[idx] != node) return;
        self.removeAtIdx(idx);
    }

    /// Returns the node whose range covers `vaddr`, or null. Each node
    /// occupies a disjoint half-open interval `[start, end)`, so the
    /// only candidate is the greatest-start-≤-vaddr neighbor.
    fn findNodeLocked(self: *VirtualMemoryManager, vaddr: VAddr) ?*VmNode {
        const idx = lowerBoundIdx(self.slice(), vaddr.addr +| 1);
        if (idx == 0) return null;
        const candidate = self.nodes[idx - 1];
        if (vaddr.addr < candidate.end()) return candidate;
        return null;
    }

    pub fn allocateAfterCursor(self: *VirtualMemoryManager, size: u64) !VAddr {
        self.lock.lock();
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
        self.lock.lock();
        defer self.lock.unlock();

        const node = try allocVmNode();
        node.* = .{
            .start = start,
            .size = size,
            .kind = .private,
            .rights = rights,
            .handle = HANDLE_NONE,
            .restart_policy = policy,
        };

        self.insertNodeLocked(node) catch |e| {
            freeVmNode(node);
            return e;
        };
    }

    pub fn deinit(self: *VirtualMemoryManager) void {
        self.lock.lock();
        defer self.lock.unlock();

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const node = self.nodes[i];
            unmapNodePages(node, self.addr_space_root, true);
            freeVmNode(node);
        }
        self.count = 0;
    }

    pub fn findNode(self: *VirtualMemoryManager, vaddr: VAddr) ?*VmNode {
        self.lock.lock();
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
            const node = s[i];
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

        self.lock.lock();
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
                const hint_free = if (upper_idx == 0)
                    true
                else
                    hint.addr >= s[upper_idx - 1].end();

                // upper: first node with start >= hint. If it starts
                // inside [hint, hint_end), the hinted range is not clear.
                const range_clear = if (upper_idx >= s.len)
                    true
                else
                    s[upper_idx].start.addr >= hint_end;

                if (hint_free and range_clear) break :blk hint;
            }
            break :blk try self.findFreeRange(size);
        };

        const node = try allocVmNode();
        node.* = .{
            .start = chosen,
            .size = size,
            .kind = .private,
            .rights = .{
                .read = max_rights.read,
                .write = max_rights.write,
                .execute = max_rights.execute,
            },
            .handle = HANDLE_NONE,
            .restart_policy = .free,
        };

        self.insertNodeLocked(node) catch |e| {
            freeVmNode(node);
            return e;
        };

        return .{ .vaddr = chosen, .node = node };
    }

    pub fn reserveStack(self: *VirtualMemoryManager, num_pages: u32) !StackResult {
        const usable_size = @as(u64, num_pages) * paging.PAGE4K;
        const total = usable_size + 2 * paging.PAGE4K;

        self.lock.lock();
        defer self.lock.unlock();

        const base_addr = try self.findFreeRange(total);
        const usable_start = base_addr.addr + paging.PAGE4K;
        const overflow_start = usable_start + usable_size;

        const underflow_node = try allocVmNode();
        underflow_node.* = .{
            .start = base_addr,
            .size = paging.PAGE4K,
            .kind = .private,
            .rights = .{},
            .handle = HANDLE_NONE,
            .restart_policy = .free,
        };

        self.insertNodeLocked(underflow_node) catch |e| {
            freeVmNode(underflow_node);
            return e;
        };

        const stack_node = try allocVmNode();
        stack_node.* = .{
            .start = VAddr.fromInt(usable_start),
            .size = usable_size,
            .kind = .private,
            .rights = .{ .read = true, .write = true },
            .handle = HANDLE_NONE,
            .restart_policy = .free,
        };

        self.insertNodeLocked(stack_node) catch |e| {
            self.removeNodeLocked(underflow_node);
            freeVmNode(underflow_node);
            freeVmNode(stack_node);
            return e;
        };

        const overflow_node = try allocVmNode();
        overflow_node.* = .{
            .start = VAddr.fromInt(overflow_start),
            .size = paging.PAGE4K,
            .kind = .private,
            .rights = .{},
            .handle = HANDLE_NONE,
            .restart_policy = .free,
        };

        self.insertNodeLocked(overflow_node) catch |e| {
            unmapNodePages(stack_node, self.addr_space_root, true);
            self.removeNodeLocked(stack_node);
            self.removeNodeLocked(underflow_node);
            freeVmNode(overflow_node);
            freeVmNode(stack_node);
            freeVmNode(underflow_node);
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
        self.lock.lock();
        defer self.lock.unlock();

        if (self.findNodeLocked(stack.guard)) |underflow_node| {
            self.removeNodeLocked(underflow_node);
            freeVmNode(underflow_node);
        }
        if (self.findNodeLocked(stack.base)) |stack_node| {
            unmapNodePages(stack_node, self.addr_space_root, true);
            self.removeNodeLocked(stack_node);
            freeVmNode(stack_node);
        }
        if (self.findNodeLocked(stack.top)) |overflow_node| {
            self.removeNodeLocked(overflow_node);
            freeVmNode(overflow_node);
        }
    }

    pub fn demandPage(self: *VirtualMemoryManager, fault_vaddr: VAddr, is_write: bool, is_exec: bool) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const node = self.findNodeLocked(fault_vaddr) orelse return error.NoMapping;

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
        self.lock.lock();
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
            if (s[i].kind != .private) return error.NonPrivateRange;
        }

        i = lo;
        while (i < hi) : (i += 1) {
            const node = s[i];
            if (node.kind != .private) continue;
            node.rights = new_rights;
            updateCommittedPages(node, self.addr_space_root, new_rights, .user);
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
        shm: *SharedMemory,
        rights: VmReservationRights,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

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

        const map_node = try allocVmNode();
        map_node.* = .{
            .start = range_start,
            .size = range_size,
            .kind = .{ .shared_memory = shm },
            .rights = .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            .handle = shm_handle,
            .restart_policy = .free,
        };

        self.insertNodeLocked(map_node) catch |e| {
            freeVmNode(map_node);
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
                    self.removeNodeLocked(map_node);
                    freeVmNode(map_node);
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
        self.lock.lock();
        defer self.lock.unlock();
        _ = vm_handle;
        _ = original_size;

        const range_start = VAddr.fromInt(original_start.addr + offset);
        const range_end_addr = range_start.addr + size;

        // §2.3.7/§2.3.47: SHM, MMIO, and virtual BAR nodes must be fully
        // contained — partial overlap returns E_INVAL. Check the boundary
        // nodes BEFORE splitting (splitAtLocked would split non-private
        // nodes, corrupting them).
        if (self.findNodeLocked(range_start)) |node| {
            if (node.kind != .private and node.start.addr < range_start.addr)
                return error.PartialOverlap;
        }
        if (self.findNodeLocked(VAddr.fromInt(range_end_addr -| 1))) |node| {
            if (node.kind != .private and node.start.addr + node.size > range_end_addr)
                return error.PartialOverlap;
        }

        // Split private nodes at range boundaries.
        try self.splitAtLocked(range_start);
        try self.splitAtLocked(VAddr.fromInt(range_end_addr));

        // UNMAP PASS: drop non-private nodes into `to_replace` so we can
        // swap them for private placeholders after the iteration — we
        // avoid mutating the array while iterating over it.
        var to_replace: [128]*VmNode = undefined;
        var replace_count: usize = 0;

        {
            const s = self.slice();
            const lo = lowerBoundIdx(s, range_start.addr);
            const hi = lowerBoundIdx(s, range_end_addr);
            var i: usize = lo;
            while (i < hi) : (i += 1) {
                const node = s[i];
                const unmap_rights: VmReservationRights = .{
                    .read = max_rights.read,
                    .write = max_rights.write,
                    .execute = max_rights.execute,
                };
                switch (node.kind) {
                    .private => {
                        unmapNodePages(node, self.addr_space_root, true);
                        node.rights = unmap_rights;
                    },
                    .shared_memory, .mmio, .virtual_bar => {
                        if (node.kind != .virtual_bar) {
                            unmapNodePages(node, self.addr_space_root, false);
                        }
                        if (replace_count < to_replace.len) {
                            to_replace[replace_count] = node;
                            replace_count += 1;
                        }
                    },
                }
            }
        }

        // Replace non-private nodes with private nodes.
        for (to_replace[0..replace_count]) |node| {
            const old_start = node.start;
            const old_size = node.size;
            const old_handle = node.handle;
            self.removeNodeLocked(node);
            freeVmNode(node);

            const replacement = allocVmNode() catch continue;
            replacement.* = .{
                .start = old_start,
                .size = old_size,
                .kind = .private,
                .rights = .{
                    .read = max_rights.read,
                    .write = max_rights.write,
                    .execute = max_rights.execute,
                },
                .handle = old_handle,
                .restart_policy = .free,
            };
            self.insertNodeLocked(replacement) catch freeVmNode(replacement);
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
        device: *DeviceRegion,
        write_combining: bool,
        rights: VmReservationRights,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

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

        const map_node = try allocVmNode();
        map_node.* = .{
            .start = range_start,
            .size = range_size,
            .kind = .{ .mmio = device },
            .rights = .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            .handle = device_handle,
            .restart_policy = .free,
        };

        self.insertNodeLocked(map_node) catch |e| {
            freeVmNode(map_node);
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
                    self.removeNodeLocked(map_node);
                    freeVmNode(map_node);
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
        device: *DeviceRegion,
        rights: VmReservationRights,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

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

        const map_node = try allocVmNode();
        map_node.* = .{
            .start = range_start,
            .size = range_size,
            .kind = .{ .virtual_bar = device },
            .rights = .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            .handle = device_handle,
            .restart_policy = .free,
        };

        self.insertNodeLocked(map_node) catch |e| {
            freeVmNode(map_node);
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
        self.lock.lock();
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
            const node = self.nodes[i];
            const free_phys = node.kind == .private;
            unmapNodePages(node, self.addr_space_root, free_phys);
            self.removeAtIdx(i);
            freeVmNode(node);
        }
    }

    pub const ReservationInfo = struct {
        start: u64,
        end: u64,
        rights: VmReservationRights,
    };

    pub fn revokeShmHandle(self: *VirtualMemoryManager, shm: *SharedMemory, reservations: []const ReservationInfo) void {
        self.lock.lock();
        defer self.lock.unlock();

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const node = self.nodes[i];
            if (node.kind != .shared_memory) continue;
            if (node.kind.shared_memory != shm) continue;
            unmapNodePages(node, self.addr_space_root, false);
            node.kind = .private;
            node.rights = findContainingRights(reservations, node.start.addr);
            node.handle = HANDLE_NONE;
            node.restart_policy = .free;
        }
    }

    pub fn revokeMmioHandle(self: *VirtualMemoryManager, device: *DeviceRegion, reservations: []const ReservationInfo) void {
        self.lock.lock();
        defer self.lock.unlock();

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const node = self.nodes[i];
            const is_mmio = node.kind == .mmio and node.kind.mmio == device;
            const is_vbar = node.kind == .virtual_bar and node.kind.virtual_bar == device;
            if (!is_mmio and !is_vbar) continue;
            if (is_mmio) unmapNodePages(node, self.addr_space_root, false);
            node.kind = .private;
            node.rights = findContainingRights(reservations, node.start.addr);
            node.handle = HANDLE_NONE;
            node.restart_policy = .free;
        }
    }

    pub fn resetForRestart(self: *VirtualMemoryManager) void {
        self.lock.lock();
        defer self.lock.unlock();

        // Walk from the end so removals can't shift nodes we haven't
        // visited yet. `.free` victims get removed outright; `.decommit`
        // just drops their backing pages; `.preserve` is a no-op.
        var i: usize = self.count;
        while (i > 0) {
            i -= 1;
            const node = self.nodes[i];
            switch (node.restart_policy) {
                .free => {
                    const free_phys = node.kind == .private;
                    unmapNodePages(node, self.addr_space_root, free_phys);
                    self.removeAtIdx(i);
                    freeVmNode(node);
                },
                .decommit => {
                    unmapNodePages(node, self.addr_space_root, true);
                },
                .preserve => {},
            }
        }
    }

    // ── Internal helpers (locked) ──────────────────────────────────────

    fn splitAtLocked(self: *VirtualMemoryManager, split_vaddr: VAddr) !void {
        const node = self.findNodeLocked(split_vaddr) orelse return;
        if (node.start.addr == split_vaddr.addr) return;

        const right = try allocVmNode();
        right.* = .{
            .start = split_vaddr,
            .size = node.end() - split_vaddr.addr,
            .kind = node.kind,
            .rights = node.rights,
            .handle = node.handle,
            .restart_policy = node.restart_policy,
        };
        node.size = split_vaddr.addr - node.start.addr;

        self.insertNodeLocked(right) catch |e| {
            node.size = right.end() - node.start.addr;
            freeVmNode(right);
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
            const node = self.nodes[idx];
            if (node.start.addr >= range_end.addr) break;
            const next = self.nodes[idx + 1];
            if (next.start.addr >= range_end.addr) break;
            if (canMerge(node, next)) {
                node.size += next.size;
                self.removeAtIdx(idx + 1);
                freeVmNode(next);
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
        const node = self.nodes[idx];
        if (node.start.addr != vaddr.addr) return;
        const prev = self.nodes[idx - 1];
        if (!canMerge(prev, node)) return;
        prev.size += node.size;
        self.removeAtIdx(idx);
        freeVmNode(node);
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
            const node = self.nodes[i];
            self.removeAtIdx(i);
            freeVmNode(node);
        }
    }

    fn hasDuplicateShmLocked(self: *VirtualMemoryManager, res_start: VAddr, res_size: u64, shm: *SharedMemory) bool {
        const s = self.slice();
        const lo = lowerBoundIdx(s, res_start.addr);
        const hi = lowerBoundIdx(s, res_start.addr + res_size);
        var i: usize = lo;
        while (i < hi) : (i += 1) {
            if (s[i].kind == .shared_memory and s[i].kind.shared_memory == shm) return true;
        }
        return false;
    }

    fn hasDuplicateMmioLocked(self: *VirtualMemoryManager, res_start: VAddr, res_size: u64, device: *DeviceRegion) bool {
        const s = self.slice();
        const lo = lowerBoundIdx(s, res_start.addr);
        const hi = lowerBoundIdx(s, res_start.addr + res_size);
        var i: usize = lo;
        while (i < hi) : (i += 1) {
            if (s[i].kind == .mmio and s[i].kind.mmio == device) return true;
        }
        return false;
    }

    fn hasDuplicateVirtualBarLocked(self: *VirtualMemoryManager, res_start: VAddr, res_size: u64, device: *DeviceRegion) bool {
        const s = self.slice();
        const lo = lowerBoundIdx(s, res_start.addr);
        const hi = lowerBoundIdx(s, res_start.addr + res_size);
        var i: usize = lo;
        while (i < hi) : (i += 1) {
            if (s[i].kind == .virtual_bar and s[i].kind.virtual_bar == device) return true;
        }
        return false;
    }

    fn hasCommittedPagesLocked(self: *VirtualMemoryManager, range_start: VAddr, range_end_addr: u64) bool {
        const s = self.slice();
        const lo = lowerBoundIdx(s, range_start.addr);
        const hi = lowerBoundIdx(s, range_end_addr);
        var i: usize = lo;
        while (i < hi) : (i += 1) {
            if (arch.paging.resolveVaddr(self.addr_space_root, s[i].start) != null) return true;
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

fn unmapNodePages(node: *VmNode, addr_space_root: PAddr, free_phys: bool) void {
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
    node: *VmNode,
    addr_space_root: PAddr,
    rights: VmReservationRights,
    privilege: PrivilegePerm,
) void {
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
