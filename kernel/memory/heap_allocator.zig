const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const intrusive_freelist = @import("intrusive_freelist.zig");
const rbt = @import("red_black_tree.zig");
const slab_alloc = @import("slab_allocator.zig");
const GRANULARITY = 8;
const MAX_ALIGN = @bitSizeOf(u8) * GRANULARITY;

const AllocHeader = packed struct(u56) {
    is_free: bool,
    block_len: u48,
    alignment: u7,
    // 8 unused bits
};

/// Scaled down by granularity (8) to fit in a single byte.
const AllocPadding = packed struct(u8) {
    header_offset: u8,
};

const AllocFooter = packed struct(u48) {
    header: u48,
    // 16 unused bits
};

/// This type is meaningless other than to ensure
/// the intrusive freelist freenode alignment and length
/// is satisfied. The allocation header and footer are not
/// factored into this size. The min len includes the alloc
/// footer size to ensure there's space for it, but the bytes
/// in the freelist entry exclude it so that it's not overwritten
/// when the freelist zeroes out the memory to store it's own metadata.
const FREELIST_ENTRY_LEN = @sizeOf(usize) * 4;
const MIN_LEN = FREELIST_ENTRY_LEN + @sizeOf(AllocFooter);
const MIN_ALIGN = @alignOf(usize);
const FreelistEntry = struct {
    bytes: [FREELIST_ENTRY_LEN]u8 align(MIN_ALIGN),
};

/// Using pop specific enables skipping the tree walk when removing freed
/// tree entries during coalescing in free(). Enabling link to list enables
/// jumping from the freelist entry to the freelist itself to check if popSpecific()
/// removed the last entry, and from there @fieldParentPtr can jump to the tree
/// entry itself to remove it with removeFromPtr() on the tree. The cost of these
/// is an extra 16 bytes required on the minimum allocation length, but the benefit
/// is you don't pay for two O(logn) tree walks if both adjacent blocks can be
/// coalesced, instead it's 3 pointer dereferences per block coalesced.
const using_popSpecific = true;
const link_to_list = true;
const Freelist = intrusive_freelist.IntrusiveFreeList(
    *FreelistEntry,
    using_popSpecific,
    link_to_list,
);

/// The tree is keyed by length, and duplicate length entries are
/// pushed into the freelist.
const TreeEntry = struct {
    bucket_len: usize,
    freelist: Freelist,

    fn cmpFn(first: TreeEntry, second: TreeEntry) std.math.Order {
        return std.math.order(first.bucket_len, second.bucket_len);
    }
};

// NOTE: Will need to add support for pushing to freelist on duplicate without using two tree walks,
// maybe a callback could be added that runs when a duplicate key is discovered on insert.
// The tree will also need a removeFromPtr() function implemented, so do this at the same time.
const duplicate_is_error = false;
const RedBlackTree = rbt.RedBlackTree(
    TreeEntry,
    TreeEntry.cmpFn,
    duplicate_is_error,
);

const stack_bootstrap = false;
const stack_size = 0;
const allocation_chunk_size = 64;
pub const TreeAllocator = slab_alloc.SlabAllocator(
    RedBlackTree.Node,
    stack_bootstrap,
    stack_size,
    allocation_chunk_size,
);

const HeapAllocator = struct {
    reserve_start: u48,
    commit_end: u48,
    reserve_end: u48,
    free_tree: RedBlackTree,

    /// Takes a contiguous virtual address space to own.
    /// The tree allocator is made public so it can be initialized
    /// by the caller, allowing them to specify the tree allocator's
    /// backing allocator, and handle the potential error upon
    /// initialization that the slab allocator can return.
    pub fn init(
        reserve_start: u48,
        reserve_end: u48,
        tree_allocator: *TreeAllocator,
    ) HeapAllocator {
        return .{
            .reserve_start = reserve_start,
            .commit_end = reserve_start,
            .reserve_end = reserve_end,
            .free_tree = RedBlackTree.init(tree_allocator.allocator()),
        };
    }

    pub fn deinit(self: *HeapAllocator) void {
        self.free_tree.deinit();
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
        _ = ret_addr;
        const self: *HeapAllocator = @alignCast(@ptrCast(ptr));
        std.debug.assert(alignment.toByteUnits() <= MAX_ALIGN);
        std.debug.assert(std.mem.isAligned(self.commit_end, @alignOf(AllocHeader)));

        const user_len: u48 = @max(MIN_LEN, @as(u48, @intCast(len)));
        const user_align: u48 = @max(MIN_ALIGN, @as(u48, @intCast(alignment.toByteUnits())));

        var block_len: u48 = 0;

        const header_offset = block_len;
        block_len += @sizeOf(AllocHeader);

        const user_block_offset = std.mem.alignForward(
            u48,
            block_len,
            user_align,
        );
        block_len = user_block_offset + user_len;

        const padding_offset = user_block_offset - @sizeOf(AllocPadding);

        std.debug.print("Alloc Header Base {}\n", .{header_offset});
        std.debug.print("Alloc Padding Base {}\n", .{padding_offset});
        std.debug.print("Alloc User Block Base {}\n\n", .{user_block_offset});

        if (self.commit_end + block_len > self.reserve_end) return null;
        self.commit_end += block_len;

        const block_base = self.commit_end - block_len;
        const header_base = block_base + header_offset;
        const padding_base = block_base + padding_offset;
        const user_block_base = block_base + user_block_offset;

        std.debug.print("Alloc Block Base {}\n", .{block_base});
        std.debug.print("Alloc Header Base {}\n", .{header_base});
        std.debug.print("Alloc Padding Base {}\n", .{padding_base});
        std.debug.print("Alloc User Block Base {}\n\n", .{user_block_base});

        var header: *AllocHeader = @ptrFromInt(header_base);
        header.is_free = false;
        header.block_len = user_len + @sizeOf(AllocFooter);
        header.alignment = @ctz(header_base + @sizeOf(AllocHeader));

        std.debug.print("Alloc User Block Len {}\n", .{user_len});
        std.debug.print("Alloc Block Len {}\n", .{header.block_len});
        std.debug.print("Alloc Max Alignment {}\n", .{header.alignment});

        var padding: *AllocPadding = @ptrFromInt(padding_base);
        padding.header_offset = @intCast(std.math.divExact(u48, user_block_base - header_base, GRANULARITY) catch unreachable);

        std.debug.print("Alloc Padding Header Offset Unscaled {} Scaled {}\n\n", .{ padding.header_offset, padding.header_offset * GRANULARITY });

        const user_ptr: [*]u8 = @ptrFromInt(user_block_base);
        return user_ptr;
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

    // no op
    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        _ = alignment;
        _ = ret_addr;
        const self: *HeapAllocator = @alignCast(@ptrCast(ptr));

        const user_addr: u48 = @intCast(@intFromPtr(buf.ptr));
        const padding_ptr: *AllocPadding = @ptrFromInt(user_addr - @sizeOf(AllocPadding));

        const header_offset = padding_ptr.header_offset * GRANULARITY;
        const header_ptr: *AllocHeader = @ptrFromInt(user_addr - header_offset);

        const end_addr = @intFromPtr(header_ptr) + @sizeOf(AllocHeader) + header_ptr.block_len;
        const footer_ptr: *AllocFooter = @ptrFromInt(end_addr - @sizeOf(AllocFooter));
        footer_ptr.header = @intCast(@intFromPtr(header_ptr));

        std.debug.print("Free Block Len {}\n", .{header_ptr.block_len});
        std.debug.print("Free Block Alignment {}\n", .{header_ptr.alignment});
        std.debug.print("Free Block State {}\n\n", .{header_ptr.is_free});

        const freelist_entry: *FreelistEntry = @ptrFromInt(@intFromPtr(header_ptr) + @sizeOf(AllocHeader));
        var freelist: Freelist = .{};
        freelist.push(freelist_entry);

        const tree_entry: TreeEntry = .{
            .bucket_len = header_ptr.block_len,
            .freelist = freelist,
        };

        self.free_tree.insert(tree_entry) catch unreachable;
    }
};

test "alloc wip" {
    const testing_allocator = std.testing.allocator;
    var tree_allocator = try TreeAllocator.init(testing_allocator);
    defer tree_allocator.deinit();

    const ten_pages = 10 * 4 * 1024;
    const memory = try testing_allocator.alloc(u8, ten_pages);
    defer testing_allocator.free(memory);

    const reserve_start: u48 = @intCast(@intFromPtr(memory.ptr));
    const reserve_end: u48 = reserve_start + @as(u48, @intCast(memory.len));

    var heap_allocator = HeapAllocator.init(
        reserve_start,
        reserve_end,
        &tree_allocator,
    );
    defer heap_allocator.deinit();

    const allocator = heap_allocator.allocator();

    const TestType = struct {
        bytes: [8]u8 align(64),
    };

    const alloc = try allocator.alloc(TestType, 1);
    allocator.free(alloc);
}
