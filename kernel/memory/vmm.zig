const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const containers = zag.utils.containers;
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

fn vmNodeCmp(a: *VmNode, b: *VmNode) std.math.Order {
    return std.math.order(a.start.addr, b.start.addr);
}

const VmTree = containers.red_black_tree.RedBlackTree(*VmNode, vmNodeCmp, true);
const VmNodeSlab = slab_mod.SlabAllocator(VmNode, false, 0, 64, true);
const VmTreeSlab = slab_mod.SlabAllocator(VmTree.Node, false, 0, 64, true);

var vm_node_slab: VmNodeSlab = undefined;
var vm_tree_slab: VmTreeSlab = undefined;

pub fn initSlabs(node_backing: std.mem.Allocator, tree_backing: std.mem.Allocator) !void {
    vm_node_slab = try VmNodeSlab.init(node_backing);
    vm_tree_slab = try VmTreeSlab.init(tree_backing);
}

fn allocVmNode() !*VmNode {
    return vm_node_slab.allocator().create(VmNode);
}

fn freeVmNode(node: *VmNode) void {
    vm_node_slab.allocator().destroy(node);
}

fn mkSentinel(vaddr: VAddr) VmNode {
    return .{ .start = vaddr, .size = 0, .kind = .private, .rights = .{}, .handle = HANDLE_NONE, .restart_policy = .free };
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
    tree: VmTree,
    range_start: VAddr,
    range_end: VAddr,
    addr_space_root: PAddr,
    lock: SpinLock,

    pub fn init(start: VAddr, end_vaddr: VAddr, root: PAddr) VirtualMemoryManager {
        return .{
            .tree = VmTree.init(vm_tree_slab.allocator()),
            .range_start = start,
            .range_end = end_vaddr,
            .addr_space_root = root,
            .lock = .{},
        };
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

        self.tree.insert(node) catch |e| {
            freeVmNode(node);
            return e;
        };
    }

    pub fn deinit(self: *VirtualMemoryManager) void {
        self.lock.lock();
        defer self.lock.unlock();

        while (self.tree.root != null) {
            // tree.root is ?*Tree.Node — removeFromPtr takes *Tree.Node, correct here
            const vm_node = self.tree.removeFromPtr(self.tree.root.?);
            unmapNodePages(vm_node, self.addr_space_root, true);
            freeVmNode(vm_node);
        }
    }

    pub fn findNode(self: *VirtualMemoryManager, vaddr: VAddr) ?*VmNode {
        self.lock.lock();
        defer self.lock.unlock();
        return findNodeLocked(&self.tree, vaddr);
    }

    fn findFreeRange(self: *VirtualMemoryManager, size: u64) !VAddr {
        var prev_end: u64 = self.range_start.addr;
        var found: ?u64 = null;

        const Ctx = struct {
            prev_end: *u64,
            needed: u64,
            found: *?u64,
            fn cb(ctx: *@This(), node: *VmNode) void {
                if (ctx.found.* != null) return;
                if (node.start.addr > ctx.prev_end.* and
                    node.start.addr - ctx.prev_end.* >= ctx.needed)
                {
                    ctx.found.* = ctx.prev_end.*;
                }
                if (node.end() > ctx.prev_end.*) ctx.prev_end.* = node.end();
            }
        };
        var ctx = Ctx{ .prev_end = &prev_end, .needed = size, .found = &found };
        var s = mkSentinel(self.range_start);
        var e = mkSentinel(self.range_end);
        self.tree.forEachInRange(&s, &e, &ctx, Ctx.cb);

        if (found == null and self.range_end.addr - prev_end >= size) {
            found = prev_end;
        }

        return if (found) |addr| VAddr.fromInt(addr) else error.OutOfMemory;
    }

    pub fn reserve(self: *VirtualMemoryManager, hint: VAddr, size: u64, max_rights: VmReservationRights) !ReserveResult {
        if (!std.mem.isAligned(size, paging.PAGE4K) or size == 0) return error.InvalidSize;

        self.lock.lock();
        defer self.lock.unlock();

        const chosen = blk: {
            if (hint.addr != 0 and
                std.mem.isAligned(hint.addr, paging.PAGE4K) and
                hint.addr >= self.range_start.addr and
                hint.addr + size <= self.range_end.addr)
            {
                var sentinel = mkSentinel(hint);
                const neighbors = self.tree.findNeighbors(&sentinel);

                // Check hint doesn't fall inside an existing node (lower bound)
                const hint_free = if (neighbors.lower) |lower|
                    hint.addr >= lower.end()
                else
                    true;

                // Check no existing node starts inside [hint, hint+size) (upper bound)
                const range_clear = if (neighbors.upper) |upper|
                    upper.start.addr >= hint.addr + size
                else
                    true;

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

        self.tree.insert(node) catch |e| {
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

        self.tree.insert(underflow_node) catch |e| {
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

        self.tree.insert(stack_node) catch |e| {
            _ = self.tree.remove(underflow_node) catch {};
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

        self.tree.insert(overflow_node) catch |e| {
            unmapNodePages(stack_node, self.addr_space_root, true);
            _ = self.tree.remove(stack_node) catch {};
            _ = self.tree.remove(underflow_node) catch {};
            freeVmNode(overflow_node);
            freeVmNode(stack_node);
            freeVmNode(underflow_node);
            return e;
        };

        const pmm_iface = pmm.global_pmm.?.allocator();
        const top_page_va = VAddr.fromInt(overflow_start - paging.PAGE4K);
        const top_page = pmm_iface.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
        @memset(std.mem.asBytes(top_page), 0);
        const top_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(top_page)), null);
        const stack_perms = rightsToMemPerms(.{ .read = true, .write = true }, .user);
        arch.mapPage(self.addr_space_root, top_phys, top_page_va, stack_perms) catch {
            pmm_iface.destroy(top_page);
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

        if (findNodeLocked(&self.tree, stack.guard)) |underflow_node| {
            _ = self.tree.remove(underflow_node) catch {};
            freeVmNode(underflow_node);
        }
        if (findNodeLocked(&self.tree, stack.base)) |stack_node| {
            unmapNodePages(stack_node, self.addr_space_root, true);
            _ = self.tree.remove(stack_node) catch {};
            freeVmNode(stack_node);
        }
        if (findNodeLocked(&self.tree, stack.top)) |overflow_node| {
            _ = self.tree.remove(overflow_node) catch {};
            freeVmNode(overflow_node);
        }
    }

    pub fn demandPage(self: *VirtualMemoryManager, fault_vaddr: VAddr, is_write: bool, is_exec: bool) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const node = findNodeLocked(&self.tree, fault_vaddr) orelse return error.NoMapping;

        // Fast path: if the page is already backed (e.g., SHM/MMIO mapping,
        // a previously faulted-in private page), this is a no-op. Check this
        // before rejecting non-private nodes so callers can blindly pre-fault
        // every page in an arbitrary user range (e.g., the proc_create ELF
        // pre-fault loop that handles both demand-paged private sources and
        // SHM-backed ELF sources).
        const page_base = VAddr.fromInt(std.mem.alignBackward(u64, fault_vaddr.addr, paging.PAGE4K));
        if (arch.resolveVaddr(self.addr_space_root, page_base) != null) return;

        if (node.kind != .private) return error.NotDemandPageable;
        if (is_write and !node.rights.write) return error.PermissionDenied;
        if (is_exec and !node.rights.execute) return error.PermissionDenied;
        if (!is_write and !is_exec and !node.rights.read) return error.PermissionDenied;

        const pmm_iface = pmm.global_pmm.?.allocator();
        const page = pmm_iface.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
        @memset(std.mem.asBytes(page), 0);

        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        const perms = rightsToMemPerms(node.rights, .user);

        arch.mapPage(self.addr_space_root, phys, page_base, perms) catch {
            pmm_iface.destroy(page);
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

        try splitAtLocked(&self.tree, range_start);
        try splitAtLocked(&self.tree, VAddr.fromInt(range_end_addr));

        // Reject if range contains non-private nodes (SHM/MMIO).
        const CheckCtx = struct {
            has_non_private: bool = false,
            fn cb(ctx: *@This(), node: *VmNode) void {
                if (node.kind != .private) ctx.has_non_private = true;
            }
        };
        var check_ctx = CheckCtx{};
        var cs = mkSentinel(range_start);
        var ce = mkSentinel(VAddr.fromInt(range_end_addr));
        self.tree.forEachInRange(&cs, &ce, &check_ctx, CheckCtx.cb);
        if (check_ctx.has_non_private) return error.NonPrivateRange;

        const Ctx = struct {
            rights: VmReservationRights,
            root: PAddr,
            fn cb(ctx: *@This(), node: *VmNode) void {
                if (node.kind != .private) return;
                node.rights = ctx.rights;
                updateCommittedPages(node, ctx.root, ctx.rights, .user);
            }
        };
        var ctx = Ctx{ .rights = new_rights, .root = self.addr_space_root };
        var s = mkSentinel(range_start);
        var e = mkSentinel(VAddr.fromInt(range_end_addr));
        self.tree.forEachInRange(&s, &e, &ctx, Ctx.cb);

        mergeRange(&self.tree, range_start, VAddr.fromInt(range_end_addr));
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

        if (hasDuplicateShm(&self.tree, original_start, original_size, shm))
            return error.DuplicateMapping;

        try splitAtLocked(&self.tree, range_start);
        try splitAtLocked(&self.tree, VAddr.fromInt(range_end_addr));

        if (hasCommittedPages(&self.tree, self.addr_space_root, range_start, range_end_addr))
            return error.CommittedPages;

        try removeRange(&self.tree, range_start, range_end_addr);

        const map_node = try allocVmNode();
        map_node.* = .{
            .start = range_start,
            .size = range_size,
            .kind = .{ .shared_memory = shm },
            .rights = .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            .handle = shm_handle,
            .restart_policy = .free,
        };

        self.tree.insert(map_node) catch |e| {
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
            for (shm.pages, 0..) |phys, i| {
                const page_virt = VAddr.fromInt(range_start.addr + @as(u64, i) * paging.PAGE4K);
                arch.mapPage(self.addr_space_root, phys, page_virt, perms) catch {
                    var j: usize = 0;
                    while (j < i) {
                        _ = arch.unmapPage(self.addr_space_root, VAddr.fromInt(range_start.addr + @as(u64, j) * paging.PAGE4K));
                        j += 1;
                    }
                    _ = self.tree.remove(map_node) catch {};
                    freeVmNode(map_node);
                    return error.OutOfMemory;
                };
            }
        }
    }

    pub fn memShmUnmap(
        self: *VirtualMemoryManager,
        shm: *SharedMemory,
        vm_handle: u64,
        original_start: VAddr,
        original_size: u64,
        max_rights: VmReservationRights,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();
        _ = vm_handle;
        _ = original_start;
        _ = original_size;

        const map_node = inOrderFind(&self.tree, struct {
            target: *SharedMemory,
            fn match(ctx: *const @This(), node: *VmNode) bool {
                return node.kind == .shared_memory and node.kind.shared_memory == ctx.target;
            }
        }{ .target = shm }) orelse return error.NotFound;

        unmapNodePages(map_node, self.addr_space_root, false);

        const old_start = map_node.start;
        const old_size = map_node.size;
        const old_handle = map_node.handle;
        _ = self.tree.remove(map_node) catch {};
        freeVmNode(map_node);

        const replacement = try allocVmNode();
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
        self.tree.insert(replacement) catch freeVmNode(replacement);

        mergeRange(&self.tree, old_start, VAddr.fromInt(old_start.addr + old_size));
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

        if (hasDuplicateMmio(&self.tree, original_start, original_size, device))
            return error.DuplicateMapping;

        try splitAtLocked(&self.tree, range_start);
        try splitAtLocked(&self.tree, VAddr.fromInt(range_end_addr));

        if (hasCommittedPages(&self.tree, self.addr_space_root, range_start, range_end_addr))
            return error.CommittedPages;

        try removeRange(&self.tree, range_start, range_end_addr);

        const map_node = try allocVmNode();
        map_node.* = .{
            .start = range_start,
            .size = range_size,
            .kind = .{ .mmio = device },
            .rights = .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            .handle = device_handle,
            .restart_policy = .free,
        };

        self.tree.insert(map_node) catch |e| {
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
                arch.mapPage(self.addr_space_root, page_phys, page_virt, perms) catch {
                    var undo: u64 = 0;
                    while (undo < mapped) {
                        _ = arch.unmapPage(self.addr_space_root, VAddr.fromInt(range_start.addr + undo));
                        undo += paging.PAGE4K;
                    }
                    _ = self.tree.remove(map_node) catch {};
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

        if (hasDuplicateVirtualBar(&self.tree, original_start, original_size, device))
            return error.DuplicateMapping;

        try splitAtLocked(&self.tree, range_start);
        try splitAtLocked(&self.tree, VAddr.fromInt(range_end_addr));

        if (hasCommittedPages(&self.tree, self.addr_space_root, range_start, range_end_addr))
            return error.CommittedPages;

        try removeRange(&self.tree, range_start, range_end_addr);

        const map_node = try allocVmNode();
        map_node.* = .{
            .start = range_start,
            .size = range_size,
            .kind = .{ .virtual_bar = device },
            .rights = .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            .handle = device_handle,
            .restart_policy = .free,
        };

        self.tree.insert(map_node) catch |e| {
            freeVmNode(map_node);
            return e;
        };

        // No page mapping — PTEs are left absent intentionally so that
        // every access traps into the page fault handler, which decodes
        // the faulting instruction and performs the port I/O.
    }

    pub fn memMmioUnmap(
        self: *VirtualMemoryManager,
        device: *DeviceRegion,
        vm_handle: u64,
        original_start: VAddr,
        original_size: u64,
        max_rights: VmReservationRights,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();
        _ = vm_handle;
        _ = original_start;
        _ = original_size;

        const map_node = inOrderFind(&self.tree, struct {
            target: *DeviceRegion,
            fn match(ctx: *const @This(), node: *VmNode) bool {
                return (node.kind == .mmio and node.kind.mmio == ctx.target) or
                    (node.kind == .virtual_bar and node.kind.virtual_bar == ctx.target);
            }
        }{ .target = device }) orelse return error.NotFound;

        // virtual_bar nodes have no mapped pages; only unmap for mmio
        if (map_node.kind == .mmio) {
            unmapNodePages(map_node, self.addr_space_root, false);
        }

        const old_start = map_node.start;
        const old_size = map_node.size;
        const old_handle = map_node.handle;
        _ = self.tree.remove(map_node) catch {};
        freeVmNode(map_node);

        const replacement = try allocVmNode();
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
        self.tree.insert(replacement) catch freeVmNode(replacement);

        mergeRange(&self.tree, old_start, VAddr.fromInt(old_start.addr + old_size));
    }

    pub fn revokeReservation(
        self: *VirtualMemoryManager,
        original_start: VAddr,
        original_size: u64,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const range_end_addr = original_start.addr + original_size;

        var to_remove: [128]*VmNode = undefined;
        var remove_count: usize = 0;

        const Ctx = struct {
            buf: *[128]*VmNode,
            count: *usize,
            fn cb(ctx: *@This(), node: *VmNode) void {
                if (ctx.count.* < 128) {
                    ctx.buf.*[ctx.count.*] = node;
                    ctx.count.* += 1;
                }
            }
        };
        var ctx = Ctx{ .buf = &to_remove, .count = &remove_count };
        var s = mkSentinel(original_start);
        var e = mkSentinel(VAddr.fromInt(range_end_addr));
        self.tree.forEachInRange(&s, &e, &ctx, Ctx.cb);

        for (to_remove[0..remove_count]) |node| {
            const free_phys = node.kind == .private;
            unmapNodePages(node, self.addr_space_root, free_phys);
            _ = self.tree.remove(node) catch {};
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

        var s = mkSentinel(self.range_start);
        var e = mkSentinel(self.range_end);

        const Ctx = struct { target: *SharedMemory, root: PAddr, res: []const ReservationInfo };
        var ctx = Ctx{ .target = shm, .root = self.addr_space_root, .res = reservations };
        self.tree.forEachInRange(&s, &e, &ctx, struct {
            fn cb(c: *Ctx, node: *VmNode) void {
                if (node.kind != .shared_memory) return;
                if (node.kind.shared_memory != c.target) return;
                unmapNodePages(node, c.root, false);
                node.kind = .private;
                node.rights = findContainingRights(c.res, node.start.addr);
                node.handle = HANDLE_NONE;
                node.restart_policy = .free;
            }
        }.cb);
    }

    pub fn revokeMmioHandle(self: *VirtualMemoryManager, device: *DeviceRegion, reservations: []const ReservationInfo) void {
        self.lock.lock();
        defer self.lock.unlock();

        var s = mkSentinel(self.range_start);
        var e = mkSentinel(self.range_end);

        const Ctx = struct { target: *DeviceRegion, root: PAddr, res: []const ReservationInfo };
        var ctx = Ctx{ .target = device, .root = self.addr_space_root, .res = reservations };
        self.tree.forEachInRange(&s, &e, &ctx, struct {
            fn cb(c: *Ctx, node: *VmNode) void {
                const is_mmio = node.kind == .mmio and node.kind.mmio == c.target;
                const is_vbar = node.kind == .virtual_bar and node.kind.virtual_bar == c.target;
                if (!is_mmio and !is_vbar) return;
                if (is_mmio) unmapNodePages(node, c.root, false);
                node.kind = .private;
                node.rights = findContainingRights(c.res, node.start.addr);
                node.handle = HANDLE_NONE;
                node.restart_policy = .free;
            }
        }.cb);
    }

    pub fn resetForRestart(self: *VirtualMemoryManager) void {
        self.lock.lock();
        defer self.lock.unlock();

        var to_remove: [128]*VmNode = undefined;
        var remove_count: usize = 0;

        var s = mkSentinel(self.range_start);
        var e = mkSentinel(self.range_end);

        const Ctx = struct {
            root: PAddr,
            buf: *[128]*VmNode,
            count: *usize,
        };
        var ctx = Ctx{ .root = self.addr_space_root, .buf = &to_remove, .count = &remove_count };
        self.tree.forEachInRange(&s, &e, &ctx, struct {
            fn cb(c: *Ctx, node: *VmNode) void {
                switch (node.restart_policy) {
                    .free => {
                        const free_phys = node.kind == .private;
                        unmapNodePages(node, c.root, free_phys);
                        if (c.count.* < 128) {
                            c.buf.*[c.count.*] = node;
                            c.count.* += 1;
                        }
                    },
                    .decommit => {
                        unmapNodePages(node, c.root, true);
                    },
                    .preserve => {},
                }
            }
        }.cb);

        for (to_remove[0..remove_count]) |node| {
            _ = self.tree.remove(node) catch {};
            freeVmNode(node);
        }
    }
};

fn findContainingRights(reservations: []const VirtualMemoryManager.ReservationInfo, addr: u64) VmReservationRights {
    for (reservations) |res| {
        if (addr >= res.start and addr < res.end) return res.rights;
    }
    return .{ .read = true, .write = true, .execute = true };
}

fn findNodeLocked(tree: *VmTree, vaddr: VAddr) ?*VmNode {
    var sentinel = mkSentinel(vaddr);
    const result = tree.findNeighbors(&sentinel);
    const lower = result.lower orelse return null;
    if (vaddr.addr < lower.end()) return lower;
    return null;
}

fn splitAtLocked(tree: *VmTree, split_vaddr: VAddr) !void {
    const node = findNodeLocked(tree, split_vaddr) orelse return;
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

    tree.insert(right) catch |e| {
        node.size = right.end() - node.start.addr;
        freeVmNode(right);
        return e;
    };
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

fn tryMergeAt(tree: *VmTree, vaddr: VAddr) void {
    const node = findNodeLocked(tree, vaddr) orelse return;
    if (node.start.addr != vaddr.addr) return;
    var sentinel_before = mkSentinel(VAddr.fromInt(vaddr.addr -| 1));
    const result = tree.findNeighbors(&sentinel_before);
    if (result.lower) |prev| {
        if (canMerge(prev, node)) {
            prev.size += node.size;
            _ = tree.remove(node) catch {};
            freeVmNode(node);
        }
    }
}

fn mergeRange(tree: *VmTree, range_start: VAddr, range_end: VAddr) void {
    tryMergeAt(tree, range_end);

    var victims: [64]*VmNode = undefined;
    var victim_count: usize = 0;
    var prev_node: ?*VmNode = null;

    var s = mkSentinel(range_start);
    var e = mkSentinel(range_end);
    const Ctx = struct {
        prev: *?*VmNode,
        buf: *[64]*VmNode,
        count: *usize,
        fn cb(ctx: *@This(), node: *VmNode) void {
            if (ctx.prev.*) |p| {
                if (canMerge(p, node) and ctx.count.* < 64) {
                    p.size += node.size;
                    ctx.buf.*[ctx.count.*] = node;
                    ctx.count.* += 1;
                    return;
                }
            }
            ctx.prev.* = node;
        }
    };
    var ctx = Ctx{ .prev = &prev_node, .buf = &victims, .count = &victim_count };
    tree.forEachInRange(&s, &e, &ctx, Ctx.cb);

    for (victims[0..victim_count]) |victim| {
        _ = tree.remove(victim) catch {};
        freeVmNode(victim);
    }

    tryMergeAt(tree, range_start);
}

fn hasDuplicateShm(tree: *VmTree, res_start: VAddr, res_size: u64, shm: *SharedMemory) bool {
    var found = false;
    const Ctx = struct { target: *SharedMemory, found: *bool };
    var ctx = Ctx{ .target = shm, .found = &found };
    var s = mkSentinel(res_start);
    var e = mkSentinel(VAddr.fromInt(res_start.addr + res_size));
    tree.forEachInRange(&s, &e, &ctx, struct {
        fn cb(c: *Ctx, node: *VmNode) void {
            if (node.kind == .shared_memory and node.kind.shared_memory == c.target) c.found.* = true;
        }
    }.cb);
    return found;
}

fn hasDuplicateVirtualBar(tree: *VmTree, res_start: VAddr, res_size: u64, device: *DeviceRegion) bool {
    var found = false;
    const Ctx = struct { target: *DeviceRegion, found: *bool };
    var ctx = Ctx{ .target = device, .found = &found };
    var s = mkSentinel(res_start);
    var e = mkSentinel(VAddr.fromInt(res_start.addr + res_size));
    tree.forEachInRange(&s, &e, &ctx, struct {
        fn cb(c: *Ctx, node: *VmNode) void {
            if (node.kind == .virtual_bar and node.kind.virtual_bar == c.target) c.found.* = true;
        }
    }.cb);
    return found;
}

fn hasDuplicateMmio(tree: *VmTree, res_start: VAddr, res_size: u64, device: *DeviceRegion) bool {
    var found = false;
    const Ctx = struct { target: *DeviceRegion, found: *bool };
    var ctx = Ctx{ .target = device, .found = &found };
    var s = mkSentinel(res_start);
    var e = mkSentinel(VAddr.fromInt(res_start.addr + res_size));
    tree.forEachInRange(&s, &e, &ctx, struct {
        fn cb(c: *Ctx, node: *VmNode) void {
            if (node.kind == .mmio and node.kind.mmio == c.target) c.found.* = true;
        }
    }.cb);
    return found;
}

fn hasCommittedPages(tree: *VmTree, root: PAddr, range_start: VAddr, range_end_addr: u64) bool {
    var committed = false;
    const Ctx = struct { root: PAddr, committed: *bool };
    var ctx = Ctx{ .root = root, .committed = &committed };
    var s = mkSentinel(range_start);
    var e = mkSentinel(VAddr.fromInt(range_end_addr));
    tree.forEachInRange(&s, &e, &ctx, struct {
        fn cb(c: *Ctx, node: *VmNode) void {
            if (arch.resolveVaddr(c.root, node.start) != null) c.committed.* = true;
        }
    }.cb);
    return committed;
}

fn removeRange(tree: *VmTree, range_start: VAddr, range_end_addr: u64) !void {
    var to_remove: [64]*VmNode = undefined;
    var count: usize = 0;

    const Ctx = struct {
        buf: *[64]*VmNode,
        count: *usize,
        fn cb(ctx: *@This(), node: *VmNode) void {
            if (ctx.count.* < 64) {
                ctx.buf.*[ctx.count.*] = node;
                ctx.count.* += 1;
            }
        }
    };
    var ctx = Ctx{ .buf = &to_remove, .count = &count };
    var s = mkSentinel(range_start);
    var e = mkSentinel(VAddr.fromInt(range_end_addr));
    tree.forEachInRange(&s, &e, &ctx, Ctx.cb);

    for (to_remove[0..count]) |node| {
        _ = tree.remove(node) catch {};
        freeVmNode(node);
    }
}

fn inOrderFind(tree: *VmTree, ctx: anytype) ?*VmNode {
    var stack: [64]?*VmTree.Node = undefined;
    var top: usize = 0;
    var current = tree.root;
    while (current != null or top > 0) {
        while (current) |n| {
            stack[top] = n;
            top += 1;
            current = n.getChild(.left);
        }
        if (top == 0) break;
        top -= 1;
        const n = stack[top].?;
        if (ctx.match(n.data)) return n.data;
        current = n.getChild(.right);
    }
    return null;
}

fn unmapNodePages(node: *VmNode, addr_space_root: PAddr, free_phys: bool) void {
    // virtual_bar nodes have no mapped pages — PTEs are intentionally absent
    if (node.kind == .virtual_bar) return;

    const pmm_iface = pmm.global_pmm.?.allocator();
    var page_addr = node.start.addr;
    while (page_addr < node.end()) {
        if (arch.unmapPage(addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
            if (free_phys and node.kind == .private) {
                const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
                pmm_iface.destroy(page);
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
        const pmm_iface = pmm.global_pmm.?.allocator();
        var page_addr = node.start.addr;
        while (page_addr < node.end()) {
            if (arch.unmapPage(addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
                if (node.kind == .private) {
                    const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
                    pmm_iface.destroy(page);
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
        if (arch.resolveVaddr(addr_space_root, vaddr) != null) {
            arch.updatePagePerms(addr_space_root, vaddr, perms);
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
