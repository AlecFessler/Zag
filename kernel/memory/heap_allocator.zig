const std = @import("std");

const rbt = @import("red_black_tree.zig");
const slab_allocator = @import("slab_allocator.zig");

const FUZZY_REMOVE_MAGIC = 0xFFFF_FFFF_FFFF_FFFF;

const TreeEntry = struct {
    addr: usize,
    alignment: usize,
    len: usize,

    fn addrCmpFn(target: TreeEntry, other: TreeEntry) std.math.Order {
        return std.math.order(target.addr, other.addr);
    }

    /// The free tree is sorted by length target for efficient best fit searches
    /// and then by alignment other to ensure alignment requirements of
    /// allocations are met and then lastly by address so that strict address
    /// equality checks can be performed if the target address is not 2^64 - 1
    /// Length equality allows up to 20% extra space before it starts
    /// matching by alignment instead
    fn freeCmpFn(target: TreeEntry, other: TreeEntry) std.math.Order {
        const slack_ratio = 5;
        const slack_allowed = target.len / slack_ratio;
        const max_len = target.len + slack_allowed;

        const len_same = target.len <= other.len and other.len < max_len;
        if (!len_same) {
            return std.math.order(target.len, other.len);
        }

        const align_order = std.math.order(target.alignment, other.alignment);
        if (align_order != .eq) {
            return align_order;
        }

        if (target.addr == FUZZY_REMOVE_MAGIC) {
            return std.math.Order.eq;
        }
        return std.math.order(target.addr, other.addr);
    }
};

const duplicate_is_error = true;
const AddrTree = rbt.RedBlackTree(
    TreeEntry,
    TreeEntry.addrCmpFn,
    duplicate_is_error,
);
const FreeTree = rbt.RedBlackTree(
    TreeEntry,
    TreeEntry.freeCmpFn,
    !duplicate_is_error,
);

const stack_bootstrap = false;
const stack_size = 0;
const allocation_chunk_size = 64;
const TreeAllocator = slab_allocator.SlabAllocator(
    FreeTree.Node,
    stack_bootstrap,
    stack_size,
    allocation_chunk_size,
);

/// Delegating allocator. Requires a backing allocator, can also act as a backing allocator.
pub const HeapAllocator = struct {
    backing_allocator: std.mem.Allocator,
    tree_allocator: TreeAllocator,
    alloc_addr_tree: AddrTree,
    free_addr_tree: AddrTree,
    free_tree: FreeTree,

    /// The backing allocator is used both by the slab allocator that the
    /// tree uses, and by the heap allocator itself when the tree doesn't
    /// contain a suitable best fit for a given allocation
    pub fn init(
        backing_allocator: std.mem.Allocator,
    ) !HeapAllocator {
        var tree_allocator = try TreeAllocator.init(backing_allocator);
        const alloc_addr_tree = AddrTree.init(tree_allocator.allocator());
        const free_addr_tree = AddrTree.init(tree_allocator.allocator());
        const free_tree = FreeTree.init(tree_allocator.allocator());
        return .{
            .backing_allocator = backing_allocator,
            .tree_allocator = tree_allocator,
            .alloc_addr_tree = alloc_addr_tree,
            .free_addr_tree = free_addr_tree,
            .free_tree = free_tree,
        };
    }

    pub fn deinit(self: *HeapAllocator) void {
        self.alloc_addr_tree.deinit();
        self.free_addr_tree.deinit();
        self.free_tree.deinit();
        self.tree_allocator.deinit();
        // for now this is assumed to use a bump allocator as a backing allocator
        // where freeing memory is a no op and currently marked unreachable
    }

    pub fn allocator(self: *HeapAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ptr: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *HeapAllocator = @alignCast(@ptrCast(ptr));
        const best_fit = self.free_tree.remove(.{
            // using alignment for addr is valid because it provides
            // the cmpFn with an address that has the required alignment
            .addr = FUZZY_REMOVE_MAGIC,
            .alignment = alignment.toByteUnits(),
            .len = len,
        }) catch {
            const mem = self.backing_allocator.rawAlloc(
                len,
                alignment,
                ret_addr,
            ) orelse return null;
            self.alloc_addr_tree.insert(.{
                .addr = @intFromPtr(mem),
                .alignment = alignment.toByteUnits(),
                .len = len,
            }) catch |e| switch (e) {
                error.OutOfMemory => return null,
                error.Duplicate => unreachable,
                error.NotFound => unreachable,
            };
            return mem;
        };
        _ = self.free_addr_tree.remove(best_fit) catch unreachable;
        self.alloc_addr_tree.insert(best_fit) catch |e| switch (e) {
            error.OutOfMemory => return null,
            error.Duplicate => unreachable,
            error.NotFound => unreachable,
        };
        return @ptrFromInt(best_fit.addr);
    }

    // no op
    // could potentially implement this using the findNeighbors tree operation
    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    // no op
    // as of now, there are no plans to implement something that would
    // be more efficient than the caller just making a larger allocation,
    // copying the data out of the old one, and then freeing the old one
    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        _ = alignment;
        _ = ret_addr;
        const self: *HeapAllocator = @alignCast(@ptrCast(ptr));
        var freed = self.alloc_addr_tree.remove(.{
            .addr = @intFromPtr(buf.ptr),
            .alignment = 0, // alignment doesn't matter for alloc tree comparison
            .len = 0, // neither does len
        }) catch unreachable;

        const neighbors = self.free_addr_tree.findNeighbors(freed);
        const lower = neighbors.lower;
        const upper = neighbors.upper;

        const can_coalesce_lower = lower != null and lower.?.addr + lower.?.len == freed.addr;
        const can_coalesce_upper = upper != null and freed.addr + freed.len == upper.?.addr;

        if (!can_coalesce_lower and !can_coalesce_upper) {
            freed.alignment = @as(usize, 1) << @intCast(@ctz(freed.addr));
            self.free_tree.insert(freed) catch unreachable;
            self.free_addr_tree.insert(freed) catch unreachable;
            return;
        }

        if (can_coalesce_lower) {
            freed.addr = lower.?.addr;
            freed.alignment = lower.?.alignment;
            freed.len = lower.?.len + freed.len;
            _ = self.free_tree.remove(lower.?) catch unreachable;
            _ = self.free_addr_tree.remove(lower.?) catch unreachable;
        }

        if (can_coalesce_upper) {
            freed.len = freed.len + upper.?.len;
            _ = self.free_tree.remove(upper.?) catch unreachable;
            _ = self.free_addr_tree.remove(upper.?) catch unreachable;
        }

        self.free_tree.insert(freed) catch unreachable;
        self.free_addr_tree.insert(freed) catch unreachable;
    }
};

test "HeapAllocator integration: allocation, free, and coalescing behavior" {
    const bump = @import("bump_allocator.zig");

    const allocator = std.testing.allocator;

    const backing_mem = try allocator.alloc(u8, 4096);
    defer allocator.free(backing_mem);

    var bump_alloc = bump.BumpAllocator.init(
        @intFromPtr(backing_mem.ptr),
        @intFromPtr(backing_mem.ptr) + backing_mem.len,
    );

    var heap = try HeapAllocator.init(bump_alloc.allocator());
    defer heap.deinit();

    const heap_allocator = heap.allocator();

    const block_size = 64;
    const first = try heap_allocator.alloc(u8, block_size);
    try std.testing.expect(heap.alloc_addr_tree.contains(.{
        .addr = @intFromPtr(first.ptr),
        .alignment = 0,
        .len = 0,
    }));

    heap_allocator.free(first);

    try std.testing.expect(heap.free_tree.contains(.{
        .addr = @intFromPtr(first.ptr),
        .alignment = @as(usize, 1) << @intCast(@ctz(@intFromPtr(first.ptr))),
        .len = block_size,
    }));

    try std.testing.expect(heap.free_addr_tree.contains(.{
        .addr = @intFromPtr(first.ptr),
        .alignment = 0,
        .len = 0,
    }));

    const second = try heap_allocator.alloc(u8, block_size - 1);
    try std.testing.expect(heap.alloc_addr_tree.contains(.{
        .addr = @intFromPtr(second.ptr),
        .alignment = 0,
        .len = block_size,
    }));

    const third = try heap_allocator.alloc(u8, block_size);
    const fourth = try heap_allocator.alloc(u8, block_size);

    heap_allocator.free(second);
    heap_allocator.free(fourth);

    heap_allocator.free(third);

    const merged_addr = @intFromPtr(first.ptr);
    const merged_len = block_size * 3;

    try std.testing.expect(heap.free_tree.contains(.{
        .addr = merged_addr,
        .alignment = @as(usize, 1) << @intCast(@ctz(merged_addr)),
        .len = merged_len,
    }));

    try std.testing.expect(heap.free_addr_tree.contains(.{
        .addr = merged_addr,
        .alignment = 0,
        .len = 0,
    }));
}
