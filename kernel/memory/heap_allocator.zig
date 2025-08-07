const std = @import("std");

const rbt = @import("../containers.zig").RedBlackTree;
const slab_allocator = @import("slab_allocator.zig");

const TreeEntry = struct {
    addr: usize,
    len: usize,

    fn allocCmpFn(first: TreeEntry, second: TreeEntry) std.math.Order {
        return std.math.order(first.addr, second.addr);
    }

    /// The free tree is sorted by length first for efficient best fit searches
    /// and then by alignment second to ensure alignment requirements of
    /// allocations are met
    /// Length equality allows up to 20% extra space before it starts
    /// matching by alignment instead
    fn freeCmpFn(first: TreeEntry, second: TreeEntry) std.math.Order {
        const slack_ratio = 5;
        const slack_allowed = first.len / slack_ratio;
        const max_len = first.len + slack_allowed;

        const len_same = first.len <= second.len and second.len < max_len;
        const len_less = first.len < second.len;
        const len_greater = first.len > second.len;

        if (len_same) {
            const first_align = @as(usize, 1) << @ctz(first.addr);
            const second_align = @as(usize, 1) << @ctz(second.addr);

            const align_same = first_align == second_align;
            const align_less = first_align < second_align;
            const align_greater = first_align > second_align;

            if (align_same) {
                return std.math.Order.eq;
            } else if (align_less) {
                return std.math.Order.lt;
            } else if (align_greater) {
                return std.math.Order.gt;
            }
        } else if (len_less) {
            return std.math.Order.lt;
        } else if (len_greater) {
            return std.math.Order.gt;
        }
    }
};

const duplicate_is_error = true;
const AllocTree = rbt.RedBlackTree(
    TreeEntry,
    TreeEntry.allocCmpFn,
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
    alloc_tree: AllocTree,
    free_tree: FreeTree,
    tree_allocator: TreeAllocator,

    /// The backing allocator is used both by the slab allocator that the
    /// tree uses, and by the heap allocator itself when the tree doesn't
    /// contain a suitable best fit for a given allocation
    pub fn init(
        backing_allocator: std.mem.Allocator,
    ) HeapAllocator {
        const tree_allocator = TreeAllocator.init(backing_allocator);
        const alloc_tree = AllocTree.init(tree_allocator.allocator());
        const free_tree = FreeTree.init(tree_allocator.allocator());
        return .{
            .backing_allocator = backing_allocator,
            .alloc_tree = alloc_tree,
            .free_tree = free_tree,
            .tree_allocator = tree_allocator,
        };
    }

    pub fn deinit(self: *HeapAllocator) void {
        self.alloc_tree.deinit();
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
        const best_fit = self.tree.remove(.{
            // using alignment for addr is valid because it provides
            // the cmpFn with an address that has the required alignment
            .addr = alignment,
            .len = len,
        }) catch {
            const mem = self.backing_allocator.rawAlloc(
                len,
                alignment,
                ret_addr,
            ) orelse return null;
            self.alloc_tree.insert(.{
                .addr = @intFromPtr(mem),
                .len = len,
            });
            return mem;
        };
        self.alloc_tree.insert(best_fit);
        return @ptrFromInt(best_fit.addr);
    }

    // no op
    // intentionally left a no op because it would only be able
    // to resize in place by up to the amount in slack that was
    // left from an earlier larger allocation that was freed
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
        const removed = self.alloc_tree.remove(.{
            .addr = @intFromPtr(buf.ptr),
            .len = 0, // len doesn't matter for alloc tree comparison
        }) catch unreachable;
        self.free_tree.insert(removed);
    }
};

// TODO: implement tests
