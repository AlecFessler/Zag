const std = @import("std");

const bitmap_freelist = @import("bitmap_freelist.zig");
const intrusive_2way_freelist = @import("intrusive_2way_freelist.zig");

const PAGE_SIZE = 4096;

const NUM_ORDERS = 11;
const ORDERS = blk: {
    var arr: [NUM_ORDERS]usize = undefined;
    for (0..NUM_ORDERS) |i| {
        arr[i] = (1 << i) * PAGE_SIZE;
    }
    break :blk arr;
};

/// Used to give the intrusive freelist a size and alignment
/// and to specify the allocation type for std.mem.Allocator.alloc()
const Page = struct {
    bytes: [PAGE_SIZE]u8 align(PAGE_SIZE),

    comptime {
        std.debug.assert(@sizeOf(Page) == PAGE_SIZE);
        std.debug.assert(@alignOf(Page) == PAGE_SIZE);
    }
};

/// Keeps track of the order for 2 pages using the minimal number of bits
const PagePairOrders = packed struct {
    even: u4,
    odd: u4,

    comptime {
        std.debug.assert(@sizeOf(PagePairOrders) == 1);
    }
};

const Intrusive2WayFreeList = intrusive_2way_freelist.Intrusive2WayFreeList(*Page);
const BitmapFreeList = bitmap_freelist.BitmapFreeList;

pub const BuddyAllocator = struct {
    start_addr: usize,
    end_addr: usize,

    /// Not a backing allocator, this is only used to allocate and free the page orders and bitmap
    init_allocator: *std.mem.Allocator,

    page_pair_orders: []PagePairOrders = undefined,
    bitmap: BitmapFreeList = undefined,
    freelists: [NUM_ORDERS]Intrusive2WayFreeList = [_]Intrusive2WayFreeList{Intrusive2WayFreeList{}} ** NUM_ORDERS,

    pub fn init(
        start_addr: usize,
        end_addr: usize,
        init_allocator: *std.mem.Allocator,
    ) !BuddyAllocator {
        std.debug.assert(end_addr > start_addr);
        const aligned_start = std.mem.alignForward(
            usize,
            start_addr,
            PAGE_SIZE,
        );
        const aligned_end = std.mem.alignBackward(
            usize,
            end_addr,
            PAGE_SIZE,
        );
        std.debug.assert(aligned_end > aligned_start);

        var self: BuddyAllocator = .{
            .start_addr = aligned_start,
            .end_addr = aligned_end,
            .init_allocator = init_allocator,
        };

        const total_bytes = aligned_end - aligned_start;
        const num_pages = total_bytes / PAGE_SIZE;
        const num_pairs = std.math.divCeil(usize, num_pages, 2) catch unreachable;

        const initially_free = false;
        self.bitmap = try BitmapFreeList.init(
            aligned_start,
            PAGE_SIZE,
            num_pages,
            initially_free,
            init_allocator,
        );
        errdefer self.bitmap.deinit();

        self.page_pair_orders = try init_allocator.alloc(PagePairOrders, num_pairs);
        errdefer init_allocator.free(self.page_pair_orders);

        var current_addr = aligned_start;
        var decrement: isize = 10;
        while (decrement >= 0) : (decrement -= 1) {
            const order: u4 = @intCast(decrement);
            const block_size = ORDERS[order];
            while (aligned_end - current_addr >= block_size) : (current_addr += block_size) {
                self.freelists[order].push(@ptrFromInt(current_addr));
                self.bitmap.setBit(current_addr, 1);
                self.setOrder(current_addr, order);
            }
            std.debug.assert(current_addr <= aligned_end);
        }
        std.debug.assert(current_addr == aligned_end);

        return self;
    }

    pub fn deinit(self: *BuddyAllocator) void {
        self.init_allocator.free(self.page_pair_orders);
        self.bitmap.deinit();
    }

    pub fn allocator(self: *BuddyAllocator) std.mem.Allocator {
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

    /// Intended to be called by alloc if the current order's freelist
    /// returned null on pop(), and assumes the caller is passing the
    /// order that they want a block returned for
    fn recursiveSplit(self: *BuddyAllocator, order: u4) ?usize {
        std.debug.assert(order < 11);

        const addr_ptr = self.freelists[order].pop() orelse {
            if (order == 10) return null;
            const recursive_addr = self.recursiveSplit(order + 1) orelse return null;

            const buddy = recursive_addr ^ ORDERS[order];
            self.setOrder(buddy, order);
            self.bitmap.setBit(buddy, 1);
            self.freelists[order].push(@ptrFromInt(buddy));

            self.setOrder(recursive_addr, order);
            return recursive_addr;
        };

        return @intFromPtr(addr_ptr);
    }

    /// Intended to be called in free every time a block is returned
    /// so that coalescing can be performed if possible
    fn recursiveMerge(self: *BuddyAllocator, addr: usize) struct { addr: usize, order: u4 } {
        const order = self.getOrder(addr);
        const buddy = addr ^ ORDERS[order];
        const is_buddy_free = self.bitmap.isFree(buddy);
        if (is_buddy_free) {
            const buddy_order = self.getOrder(buddy);
            if (buddy_order == order) {
                const lower_half = @min(addr, buddy);
                const upper_half = @max(addr, buddy);

                self.bitmap.setBit(lower_half, 0);
                self.bitmap.setBit(upper_half, 0);
                _ = self.freelists[order].pop_specific(@ptrFromInt(buddy));
                self.setOrder(lower_half, order + 1);

                return self.recursiveMerge(lower_half);
            }
        }

        return .{ .addr = addr, .order = order };
    }

    fn getOrder(self: *BuddyAllocator, addr: usize) u4 {
        const page_idx = (addr - self.start_addr) / PAGE_SIZE;
        const pair_idx = page_idx / 2;
        const is_odd = page_idx % 2 == 1;
        if (is_odd) {
            return self.page_pair_orders[pair_idx].odd;
        } else {
            return self.page_pair_orders[pair_idx].even;
        }
    }

    fn setOrder(self: *BuddyAllocator, addr: usize, order: u4) void {
        const page_idx = (addr - self.start_addr) / PAGE_SIZE;
        const pair_idx = page_idx / 2;
        const is_odd = page_idx % 2 == 1;
        if (is_odd) {
            self.page_pair_orders[pair_idx].odd = order;
        } else {
            self.page_pair_orders[pair_idx].even = order;
        }
    }

    fn alloc(
        ptr: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = alignment;
        _ = ret_addr;
        std.debug.assert(len % PAGE_SIZE == 0);
        const self: *BuddyAllocator = @alignCast(@ptrCast(ptr));

        const num_pages = len / PAGE_SIZE;
        const order: u4 = @intCast(@ctz(@as(u32, @intCast(num_pages))));
        std.debug.assert(order < 11);

        const addr = self.recursiveSplit(order) orelse return null;
        self.bitmap.setBit(addr, 0);
        return @ptrFromInt(addr);
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
        const self: *BuddyAllocator = @alignCast(@ptrCast(ptr));
        const addr = @intFromPtr(buf.ptr);
        const result = self.recursiveMerge(addr);
        self.bitmap.setBit(result.addr, 1);
        self.freelists[result.order].push(@ptrFromInt(result.addr));
    }
};

test "buddy allocator initializes expected pages and orders correctly" {
    var allocator = std.testing.allocator;

    var total_size: usize = 10 * ORDERS[10];
    const skip_order: usize = 5;
    for (0..NUM_ORDERS - 1) |i| {
        if (i == skip_order) continue;
        total_size += ORDERS[i];
    }

    const memory = try allocator.alignedAlloc(u8, PAGE_SIZE, total_size);
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        &allocator,
    );
    defer buddy.deinit();

    const expected = [_]struct {
        page_index: usize,
        order: u4,
    }{
        .{ .page_index = 0, .order = 10 },
        .{ .page_index = 1024, .order = 10 },
        .{ .page_index = 2048, .order = 10 },
        .{ .page_index = 3072, .order = 10 },
        .{ .page_index = 4096, .order = 10 },
        .{ .page_index = 5120, .order = 10 },
        .{ .page_index = 6144, .order = 10 },
        .{ .page_index = 7168, .order = 10 },
        .{ .page_index = 8192, .order = 10 },
        .{ .page_index = 9216, .order = 10 },
        .{ .page_index = 10240, .order = 9 },
        .{ .page_index = 10752, .order = 8 },
        .{ .page_index = 11008, .order = 7 },
        .{ .page_index = 11136, .order = 6 },
        .{ .page_index = 11200, .order = 4 },
        .{ .page_index = 11216, .order = 3 },
        .{ .page_index = 11224, .order = 2 },
        .{ .page_index = 11228, .order = 1 },
        .{ .page_index = 11230, .order = 0 },
    };

    for (expected) |entry| {
        const addr = start_addr + entry.page_index * PAGE_SIZE;
        const pair_idx = entry.page_index / 2;
        const is_odd = entry.page_index % 2 == 1;

        try std.testing.expect(buddy.bitmap.isFree(addr));

        if (is_odd) {
            try std.testing.expectEqual(entry.order, buddy.page_pair_orders[pair_idx].odd);
        } else {
            try std.testing.expectEqual(entry.order, buddy.page_pair_orders[pair_idx].even);
        }
    }

    const total_pages = total_size / PAGE_SIZE;
    for (0..total_pages) |page_idx| {
        const addr = start_addr + page_idx * PAGE_SIZE;
        var is_expected = false;

        for (expected) |entry| {
            if (entry.page_index == page_idx) {
                is_expected = true;
                break;
            }
        }

        if (!is_expected) {
            try std.testing.expect(!buddy.bitmap.isFree(addr));
        }
    }
}

test "buddy allocator init fails with failing allocator" {
    var allocator = std.testing.failing_allocator;

    var test_allocator = std.testing.allocator;
    const memory = try test_allocator.alignedAlloc(u8, PAGE_SIZE, 5 * ORDERS[10]);
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + 5 * ORDERS[10];

    try std.testing.expectError(
        error.OutOfMemory,
        BuddyAllocator.init(
            start_addr,
            end_addr,
            &allocator,
        ),
    );
}

test "recursiveSplit splits larger blocks into smaller ones" {
    var allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(u8, PAGE_SIZE, ORDERS[1]);
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[1];

    var buddy = try BuddyAllocator.init(start_addr, end_addr, &allocator);
    defer buddy.deinit();

    try std.testing.expect(buddy.freelists[1].head != null);
    try std.testing.expect(buddy.freelists[0].head == null);

    const addr1 = buddy.recursiveSplit(0).?;

    try std.testing.expectEqual(@as(u4, 0), buddy.getOrder(addr1));

    try std.testing.expect(buddy.freelists[0].head != null);
    try std.testing.expect(buddy.freelists[1].head == null);

    const addr2 = buddy.recursiveSplit(0).?;
    try std.testing.expectEqual(@as(u4, 0), buddy.getOrder(addr2));

    try std.testing.expect(buddy.freelists[0].head == null);

    const diff = if (addr2 > addr1) addr2 - addr1 else addr1 - addr2;
    try std.testing.expectEqual(ORDERS[0], diff);
}

test "recursiveMerge coalesces adjacent buddies and returns final state" {
    var allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(u8, PAGE_SIZE, ORDERS[1]);
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[1];

    var buddy = try BuddyAllocator.init(start_addr, end_addr, &allocator);
    defer buddy.deinit();

    const addr1 = buddy.recursiveSplit(0).?;
    const addr2 = buddy.recursiveSplit(0).?;

    try std.testing.expect(buddy.getOrder(addr1) == 0);
    try std.testing.expect(buddy.getOrder(addr2) == 0);

    buddy.bitmap.setBit(addr1, 1);
    buddy.freelists[0].push(@ptrFromInt(addr1));

    buddy.bitmap.setBit(addr2, 1);
    const result = buddy.recursiveMerge(addr2);

    const expected_lower = @min(addr1, addr2);
    try std.testing.expectEqual(expected_lower, result.addr);
    try std.testing.expectEqual(@as(u4, 1), result.order);
}

test "alloc and free work together" {
    var test_allocator = std.testing.allocator;

    const memory = try test_allocator.alignedAlloc(u8, PAGE_SIZE, ORDERS[3]);
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[3];

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        &test_allocator,
    );
    defer buddy.deinit();

    var allocator = buddy.allocator();

    const ptr1 = try allocator.alloc(u8, ORDERS[1]);
    try std.testing.expectEqual(@as(usize, ORDERS[1]), ptr1.len);

    const ptr2 = try allocator.alloc(u8, ORDERS[0]);
    try std.testing.expectEqual(@as(usize, ORDERS[0]), ptr2.len);

    allocator.free(ptr1);
    allocator.free(ptr2);

    try std.testing.expect(buddy.freelists[3].head != null);
}

test "complex allocation and deallocation with state verification" {
    var test_allocator = std.testing.allocator;

    const total_size: usize = ORDERS[1];

    const memory = try test_allocator.alignedAlloc(u8, PAGE_SIZE, total_size);
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(start_addr, end_addr, &test_allocator);
    defer buddy.deinit();

    var allocator = buddy.allocator();

    const ptr1 = try allocator.alloc(u8, ORDERS[0]);
    const addr1 = @intFromPtr(ptr1.ptr);

    const ptr2 = try allocator.alloc(u8, ORDERS[0]);
    const addr2 = @intFromPtr(ptr2.ptr);

    const buddy_diff = if (addr2 > addr1) addr2 - addr1 else addr1 - addr2;
    try std.testing.expectEqual(ORDERS[0], buddy_diff);

    const order1 = buddy.getOrder(addr1);
    const order2 = buddy.getOrder(addr2);
    try std.testing.expectEqual(@as(u4, 0), order1);
    try std.testing.expectEqual(@as(u4, 0), order2);

    const buddy1 = addr1 ^ ORDERS[0];
    const buddy2 = addr2 ^ ORDERS[0];
    try std.testing.expect(buddy1 == addr2 or buddy2 == addr1);

    allocator.free(ptr1);
    allocator.free(ptr2);

    const final_ptr = try allocator.alloc(u8, total_size);
    try std.testing.expectEqual(total_size, final_ptr.len);
    allocator.free(final_ptr);
}
