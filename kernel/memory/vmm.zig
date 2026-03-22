const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const containers = zag.containers;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const slab_mod = zag.memory.slab_allocator;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PrivilegePerm = zag.perms.privilege.PrivilegePerm;
const SharedMemory = zag.memory.shared.SharedMemory;
const SpinLock = zag.sched.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;
const VmReservationRights = zag.perms.permissions.VmReservationRights;

pub const HANDLE_NONE: u64 = std.math.maxInt(u64);

pub const PageRights = struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
};

pub const VmNode = struct {
    start: VAddr,
    size: u64,
    kind: union(enum) {
        private: void,
        shared_memory: *SharedMemory,
        mmio: *DeviceRegion,
    },
    rights: PageRights,
    handle: u64,

    pub fn end(self: *const VmNode) u64 {
        return self.start.addr + self.size;
    }
};

fn vmNodeCmp(a: *VmNode, b: *VmNode) std.math.Order {
    return std.math.order(a.start.addr, b.start.addr);
}

const VmTree = containers.red_black_tree.RedBlackTree(*VmNode, vmNodeCmp, true);
const VmNodeSlab = slab_mod.SlabAllocator(VmNode, false, 0, 64);
const VmTreeSlab = slab_mod.SlabAllocator(VmTree.Node, false, 0, 64);

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
    return .{ .start = vaddr, .size = 0, .kind = .private, .rights = .{}, .handle = HANDLE_NONE };
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

        _ = max_rights;

        const chosen = blk: {
            if (hint.addr != 0 and
                std.mem.isAligned(hint.addr, paging.PAGE4K) and
                hint.addr >= self.range_start.addr and
                hint.addr + size <= self.range_end.addr and
                findNodeLocked(&self.tree, hint) == null and
                findNodeLocked(&self.tree, VAddr.fromInt(hint.addr + size - paging.PAGE4K)) == null)
            {
                break :blk hint;
            }
            break :blk try self.findFreeRange(size);
        };

        const node = try allocVmNode();
        node.* = .{
            .start = chosen,
            .size = size,
            .kind = .private,
            .rights = .{},
            .handle = HANDLE_NONE,
        };

        self.tree.insert(node) catch |e| {
            freeVmNode(node);
            return e;
        };

        return .{ .vaddr = chosen, .node = node };
    }

    pub fn reserveStack(self: *VirtualMemoryManager, num_pages: u32) !StackResult {
        const total = (@as(u64, num_pages) + 1) * paging.PAGE4K;

        self.lock.lock();
        defer self.lock.unlock();

        const base_addr = try self.findFreeRange(total);

        const guard_node = try allocVmNode();
        guard_node.* = .{
            .start = base_addr,
            .size = paging.PAGE4K,
            .kind = .private,
            .rights = .{},
            .handle = HANDLE_NONE,
        };

        self.tree.insert(guard_node) catch |e| {
            freeVmNode(guard_node);
            return e;
        };

        const stack_node = try allocVmNode();
        stack_node.* = .{
            .start = VAddr.fromInt(base_addr.addr + paging.PAGE4K),
            .size = @as(u64, num_pages) * paging.PAGE4K,
            .kind = .private,
            .rights = .{ .read = true, .write = true },
            .handle = HANDLE_NONE,
        };

        self.tree.insert(stack_node) catch |e| {
            _ = self.tree.remove(guard_node) catch {};
            freeVmNode(guard_node);
            freeVmNode(stack_node);
            return e;
        };

        return .{
            .guard = base_addr,
            .base = VAddr.fromInt(base_addr.addr + paging.PAGE4K),
            .top = VAddr.fromInt(base_addr.addr + total),
        };
    }

    pub fn reclaimStack(self: *VirtualMemoryManager, stack: zag.memory.stack.Stack) void {
        self.lock.lock();
        defer self.lock.unlock();

        if (findNodeLocked(&self.tree, stack.guard)) |guard_node| {
            _ = self.tree.remove(guard_node) catch {};
            freeVmNode(guard_node);
        }
        if (findNodeLocked(&self.tree, stack.base)) |stack_node| {
            unmapNodePages(stack_node, self.addr_space_root, true);
            _ = self.tree.remove(stack_node) catch {};
            freeVmNode(stack_node);
        }
    }

    pub fn demandPage(self: *VirtualMemoryManager, fault_vaddr: VAddr, is_write: bool, is_exec: bool) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const node = findNodeLocked(&self.tree, fault_vaddr) orelse return error.NoMapping;

        if (node.kind != .private) return error.NotDemandPageable;
        if (is_write and !node.rights.write) return error.PermissionDenied;
        if (is_exec and !node.rights.execute) return error.PermissionDenied;
        if (!is_write and !is_exec and !node.rights.read) return error.PermissionDenied;

        const page_base = VAddr.fromInt(std.mem.alignBackward(u64, fault_vaddr.addr, paging.PAGE4K));
        if (arch.resolveVaddr(self.addr_space_root, page_base) != null) return;

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

    pub fn vm_perms(
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

        const new_rights_page = PageRights{
            .read = new_rights.read,
            .write = new_rights.write,
            .execute = new_rights.execute,
        };

        const Ctx = struct {
            rights: PageRights,
            root: PAddr,
            fn cb(ctx: *@This(), node: *VmNode) void {
                if (node.kind != .private) return;
                node.rights = ctx.rights;
                updateCommittedPages(node, ctx.root, ctx.rights, .user);
            }
        };
        var ctx = Ctx{ .rights = new_rights_page, .root = self.addr_space_root };
        var s = mkSentinel(range_start);
        var e = mkSentinel(VAddr.fromInt(range_end_addr));
        self.tree.forEachInRange(&s, &e, &ctx, Ctx.cb);
    }

    pub fn shm_map(
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
        _ = original_size;
        _ = vm_handle;

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
        };

        self.tree.insert(map_node) catch |e| {
            freeVmNode(map_node);
            return e;
        };

        const perms = rightsToMemPerms(
            .{ .read = rights.read, .write = rights.write, .execute = rights.execute },
            .user,
        );

        for (shm.pages, 0..) |phys, i| {
            const page_virt = VAddr.fromInt(range_start.addr + @as(u64, i) * paging.PAGE4K);
            arch.mapPage(self.addr_space_root, phys, page_virt, perms) catch {
                var j: usize = 0;
                while (j < i) : (j += 1) {
                    _ = arch.unmapPage(self.addr_space_root, VAddr.fromInt(range_start.addr + @as(u64, j) * paging.PAGE4K));
                }
                _ = self.tree.remove(map_node) catch {};
                freeVmNode(map_node);
                return error.OutOfMemory;
            };
        }
    }

    pub fn shm_unmap(
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
        _ = max_rights;

        const map_node = inOrderFind(&self.tree, struct {
            target: *SharedMemory,
            fn match(ctx: *const @This(), node: *VmNode) bool {
                return node.kind == .shared_memory and node.kind.shared_memory == ctx.target;
            }
        }{ .target = shm }) orelse return error.NotFound;

        unmapNodePages(map_node, self.addr_space_root, false);

        const old_start = map_node.start;
        const old_size = map_node.size;
        _ = self.tree.remove(map_node) catch {};
        freeVmNode(map_node);

        const replacement = try allocVmNode();
        replacement.* = .{
            .start = old_start,
            .size = old_size,
            .kind = .private,
            .rights = .{},
            .handle = HANDLE_NONE,
        };
        self.tree.insert(replacement) catch freeVmNode(replacement);
    }

    pub fn mmio_map(
        self: *VirtualMemoryManager,
        device_handle: u64,
        vm_handle: u64,
        original_start: VAddr,
        original_size: u64,
        offset: u64,
        device: *DeviceRegion,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const range_start = VAddr.fromInt(original_start.addr + offset);
        const range_size = device.size;
        const range_end_addr = range_start.addr + range_size;
        _ = original_size;
        _ = vm_handle;

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
            .rights = .{ .read = true, .write = true },
            .handle = device_handle,
        };

        self.tree.insert(map_node) catch |e| {
            freeVmNode(map_node);
            return e;
        };

        const perms = MemoryPerms{
            .write_perm = .write,
            .execute_perm = .no_execute,
            .cache_perm = .not_cacheable,
            .global_perm = .not_global,
            .privilege_perm = .user,
        };

        var mapped: u64 = 0;
        while (mapped < range_size) : (mapped += paging.PAGE4K) {
            const page_phys = PAddr.fromInt(device.phys_base.addr + mapped);
            const page_virt = VAddr.fromInt(range_start.addr + mapped);
            arch.mapPage(self.addr_space_root, page_phys, page_virt, perms) catch {
                var undo: u64 = 0;
                while (undo < mapped) : (undo += paging.PAGE4K) {
                    _ = arch.unmapPage(self.addr_space_root, VAddr.fromInt(range_start.addr + undo));
                }
                _ = self.tree.remove(map_node) catch {};
                freeVmNode(map_node);
                return error.OutOfMemory;
            };
        }
    }

    pub fn mmio_unmap(
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
        _ = max_rights;

        const map_node = inOrderFind(&self.tree, struct {
            target: *DeviceRegion,
            fn match(ctx: *const @This(), node: *VmNode) bool {
                return node.kind == .mmio and node.kind.mmio == ctx.target;
            }
        }{ .target = device }) orelse return error.NotFound;

        unmapNodePages(map_node, self.addr_space_root, false);

        const old_start = map_node.start;
        const old_size = map_node.size;
        _ = self.tree.remove(map_node) catch {};
        freeVmNode(map_node);

        const replacement = try allocVmNode();
        replacement.* = .{
            .start = old_start,
            .size = old_size,
            .kind = .private,
            .rights = .{},
            .handle = HANDLE_NONE,
        };
        self.tree.insert(replacement) catch freeVmNode(replacement);
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

    pub fn revokeShmHandle(self: *VirtualMemoryManager, shm: *SharedMemory) void {
        self.lock.lock();
        defer self.lock.unlock();

        var s = mkSentinel(self.range_start);
        var e = mkSentinel(self.range_end);

        const Ctx = struct { target: *SharedMemory, root: PAddr };
        var ctx = Ctx{ .target = shm, .root = self.addr_space_root };
        self.tree.forEachInRange(&s, &e, &ctx, struct {
            fn cb(c: *Ctx, node: *VmNode) void {
                if (node.kind != .shared_memory) return;
                if (node.kind.shared_memory != c.target) return;
                unmapNodePages(node, c.root, false);
                node.kind = .private;
                node.rights = .{};
                node.handle = HANDLE_NONE;
            }
        }.cb);
    }

    pub fn revokeMmioHandle(self: *VirtualMemoryManager, device: *DeviceRegion) void {
        self.lock.lock();
        defer self.lock.unlock();

        var s = mkSentinel(self.range_start);
        var e = mkSentinel(self.range_end);

        const Ctx = struct { target: *DeviceRegion, root: PAddr };
        var ctx = Ctx{ .target = device, .root = self.addr_space_root };
        self.tree.forEachInRange(&s, &e, &ctx, struct {
            fn cb(c: *Ctx, node: *VmNode) void {
                if (node.kind != .mmio) return;
                if (node.kind.mmio != c.target) return;
                unmapNodePages(node, c.root, false);
                node.kind = .private;
                node.rights = .{};
                node.handle = HANDLE_NONE;
            }
        }.cb);
    }

    pub fn resetForRestart(self: *VirtualMemoryManager) void {
        self.lock.lock();
        defer self.lock.unlock();

        var s = mkSentinel(self.range_start);
        var e = mkSentinel(self.range_end);

        const Ctx = struct { root: PAddr };
        var ctx = Ctx{ .root = self.addr_space_root };
        self.tree.forEachInRange(&s, &e, &ctx, struct {
            fn cb(c: *Ctx, node: *VmNode) void {
                if (node.kind != .private) return;
                unmapNodePages(node, c.root, true);
            }
        }.cb);
    }
};

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
    };
    node.size = split_vaddr.addr - node.start.addr;

    tree.insert(right) catch |e| {
        node.size = right.end() - node.start.addr;
        freeVmNode(right);
        return e;
    };
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
    const pmm_iface = pmm.global_pmm.?.allocator();
    var page_addr = node.start.addr;
    while (page_addr < node.end()) : (page_addr += paging.PAGE4K) {
        if (arch.unmapPage(addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
            if (free_phys and node.kind == .private) {
                const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
                pmm_iface.destroy(page);
            }
        }
    }
}

fn updateCommittedPages(
    node: *VmNode,
    addr_space_root: PAddr,
    rights: PageRights,
    privilege: PrivilegePerm,
) void {
    const perms = rightsToMemPerms(rights, privilege);
    var page_addr = node.start.addr;
    while (page_addr < node.end()) : (page_addr += paging.PAGE4K) {
        const vaddr = VAddr.fromInt(page_addr);
        if (arch.resolveVaddr(addr_space_root, vaddr) != null) {
            arch.updatePagePerms(addr_space_root, vaddr, perms);
        }
    }
}

fn rightsToMemPerms(rights: PageRights, privilege: PrivilegePerm) MemoryPerms {
    return .{
        .write_perm = if (rights.write) .write else .no_write,
        .execute_perm = if (rights.execute) .execute else .no_execute,
        .cache_perm = .write_back,
        .global_perm = if (privilege == .kernel) .global else .not_global,
        .privilege_perm = privilege,
    };
}
