const std = @import("std");

const rbt = @import("red_black_tree.zig");
const slab_allocator = @import("slab_allocator.zig");
const intrusive_freelist = @import("intrusive_freelist.zig");

/// Placed at the start of an allocation.
/// May be some number of bytes away from
/// the user pointer due to alignment requirements.
const AllocHeader = packed struct {
    is_free: bool,
    alloc_len: u63,

    comptime {
        std.debug.assert(@sizeOf(AllocHeader == 8));
    }
};

/// Placed right before user pointer in an allocation
/// to indicate how far back the alloc header is at.
/// This is included in the len, so this is the offset
/// from the user pointer backward.
const AllocPadding = struct {
    len: usize,
};

/// Placed at the end of an allocation once it is free,
/// indicates how far back the alloc header is at.
const AllocFooter = struct {
    header_addr: usize,
};

/// Only either the padding or footer will exist, as the padding is set
/// upon allocation and the footer is set upon freeing.
/// The max is used in case if the sizes are ever desynced.
const METADATA_SIZE = @sizeOf(AllocHeader) + @max(@sizeOf(AllocFooter), @sizeOf(AllocPadding));

/// This type is not meaningful in any sense other than
/// to make a minimum size guarantee to the intrusive freelist.
const FreelistEntry = struct {
    bytes: [METADATA_SIZE + 1]u8,
};

/// Used as the value of a red black tree keyed by length.
///
/// Using pop specific makes it doubly linked and allows
/// for O(1) jumps to remove items without walking the tree
/// or the list during coalescing.
///
/// Enabling link to base makes each node link back to the
/// freelist itself, so we can check if we emptied it during
/// popSpecific, allowing us to free the containing tree node
/// by grabbing it with the @fieldParentPtr builtin.
const using_popSpecific = true;
const link_to_base = true;
const Freelist = intrusive_freelist.IntrusiveFreeList(
    FreelistEntry,
    using_popSpecific,
    link_to_base,
);

/// Keyed by length, stores the max alignment of any entry
/// in the freelist so that it can be skipped if it won't
/// satisfy alignment requirements during an allocation.
const TreeEntry = struct {
    bucket_len: usize,
    max_align_in_bucket: usize,
    freelist: Freelist,

    fn treeCmpFn(first: TreeEntry, second: TreeEntry) std.math.Order {
        return std.math.order(first.bucket_len, second.bucket_len);
    }

    fn makeKey(len: usize) TreeEntry {
        return .{
            .bucket_len = len,
            .max_align_in_bucket = 0,
            .freelist = .{},
        };
    }
};

/// Stores entries keyed by length, and duplicate length
/// entries are pushed into the freelist. As a result,
/// any attempt to insert a duplicate is an error.
const duplicate_is_error = true;
const RedBlackTree = rbt.RedBlackTree(
    TreeEntry,
    TreeEntry.treeCmpFn,
    duplicate_is_error,
);

/// Minimizes fragmentation from tree node allocations
/// by batch allocating them in a contiguous slice.
const stack_bootstrap = false;
const stack_size = 0;
const allocation_chunk_size = 64;
pub const SlabAllocator = slab_allocator.SlabAllocator(
    RedBlackTree.Node,
    stack_bootstrap,
    stack_size,
    allocation_chunk_size,
);

pub const HeapAllocator = struct {
    backing_allocator: std.mem.Allocator,
    tree: RedBlackTree,

    pub fn init(
        backing_allocator: std.mem.Allocator,
        tree_allocator: SlabAllocator,
    ) HeapAllocator {
        return .{
            .backing_allocator = backing_allocator,
            .tree = RedBlackTree.init(tree_allocator.allocator()),
        };
    }

    pub fn deinit(self: *HeapAllocator) void {
        self.tree.deinit();
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

        const min_needed = len + METADATA_SIZE + alignment.toByteUnits();
        const slack_allowed = min_needed / 4;
        const max_allowed = min_needed + slack_allowed;

        const lower_bound = TreeEntry.makeKey(min_needed);
        const upper_bound = TreeEntry.makeKey(max_allowed);
        const block = self.tree.removeWithRange(lower_bound, upper_bound) catch |e| {
            std.debug.assert(e != error.NotFound);
            // allocate block, place header then padding, return user ptr
        };
        // place header then padding, return user ptr
    }

    // no op
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
    }
};
