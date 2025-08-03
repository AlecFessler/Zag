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

/// Just used to give the intrusive freelist a size and alignment
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
    allocator: *std.mem.Allocator,

    page_pair_orders: []PagePairOrders = undefined,
    bitmap: BitmapFreeList = undefined,
    freelists: [NUM_ORDERS]Intrusive2WayFreeList = [_]Intrusive2WayFreeList{Intrusive2WayFreeList{}} ** NUM_ORDERS,

    pub fn init(
        start_addr: usize,
        end_addr: usize,
        allocator: *std.mem.Allocator,
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
            .allocator = allocator,
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
            allocator,
        );
        errdefer self.bitmap.deinit();

        self.page_pair_orders = try allocator.alloc(PagePairOrders, num_pairs);
        errdefer allocator.free(self.page_pair_orders);

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
        self.allocator.free(self.page_pair_orders);
        self.bitmap.deinit();
    }

    /// Intended to be called by alloc if the current order's freelist
    /// returned null on pop(), and assumes the caller is passing the
    /// order that they want a block returned for
    fn recursiveSplit(self: *BuddyAllocator, order: u4) ?usize {
        std.debug.assert(order < 11);

        const addr_ptr = self.freelists[order].pop() orelse blk: {
            if (order == 10) return null;
            const recursive_addr = self.recursiveSplit(order + 1) orelse return null;

            const buddy = recursive_addr ^ ORDERS[order];
            self.setOrder(buddy, order);
            self.bitmap.setBit(buddy, 1);
            self.freelists[order].push(@ptrFromInt(buddy));

            break :blk @as(*Page, @ptrFromInt(recursive_addr));
        };

        return @intFromPtr(addr_ptr);
    }

    /// Intended to be called in free every time a block is returned
    /// so that coalescing can be performed if possible
    fn recursiveMerge(self: *BuddyAllocator, addr: usize) void {
        const order = self.getOrder(addr);
        const buddy = addr ^ ORDERS[order];

        if (self.bitmap.isFree(buddy)) {
            const buddy_order = self.getOrder(buddy);
            if (buddy_order == order) {
                const lower_half = @min(addr, buddy);
                const upper_half = @max(addr, buddy);

                self.setOrder(lower_half, order + 1);
                self.bitmap.setBit(upper_half, 0);
                self.recursiveMerge(lower_half);
            }
        }
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

    // allocator and interface
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

    const memory = try allocator.alignedAlloc(u8, PAGE_SIZE, 28 * 1024);
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + 28 * 1024;

    var buddy = try BuddyAllocator.init(start_addr, end_addr, &allocator);
    defer buddy.deinit();

    try std.testing.expect(buddy.freelists[2].head != null);
    try std.testing.expect(buddy.freelists[1].head != null);
    try std.testing.expect(buddy.freelists[0].head != null);
    try std.testing.expect(buddy.freelists[3].head == null);

    const addr1 = buddy.recursiveSplit(0);
    try std.testing.expect(addr1 != null);

    try std.testing.expect(buddy.freelists[0].head == null);

    const addr2 = buddy.recursiveSplit(0);
    try std.testing.expect(addr2 != null);

    try std.testing.expect(buddy.freelists[0].head != null);
    try std.testing.expect(buddy.freelists[1].head == null);

    try std.testing.expect(addr1.? != addr2.?);
    try std.testing.expect(addr1.? % PAGE_SIZE == 0);
    try std.testing.expect(addr2.? % PAGE_SIZE == 0);
}

test "recursiveMerge coalesces adjacent buddies" {
    var allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(u8, PAGE_SIZE, 2 * ORDERS[1]);
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + 2 * ORDERS[1];

    var buddy = try BuddyAllocator.init(start_addr, end_addr, &allocator);
    defer buddy.deinit();

    try std.testing.expect(buddy.freelists[1].head != null);
    try std.testing.expect(buddy.freelists[2].head == null);

    const addr1 = buddy.recursiveSplit(0).?;
    const addr3 = buddy.recursiveSplit(0).?;

    try std.testing.expect(buddy.freelists[0].head == null);
    try std.testing.expect(buddy.freelists[1].head == null);
    try std.testing.expect(buddy.freelists[2].head == null);

    buddy.bitmap.setBit(addr1, 1);
    buddy.recursiveMerge(addr1);

    try std.testing.expect(buddy.freelists[1].head != null);

    buddy.bitmap.setBit(addr3, 1);
    buddy.recursiveMerge(addr3);

    const order1_addr = @intFromPtr(buddy.freelists[1].pop().?);
    buddy.bitmap.setBit(order1_addr, 1);
    buddy.recursiveMerge(order1_addr);

    try std.testing.expect(buddy.freelists[2].head != null);
    try std.testing.expect(buddy.freelists[1].head == null);
    try std.testing.expect(buddy.freelists[0].head == null);
}
