const std = @import("std");

const bitmap_freelist = @import("bitmap_freelist.zig");

const BitmapFreeList = bitmap_freelist.BitmapFreeList;

const PAGE_SIZE = 4096;

const PagePairOrders = packed struct {
    even: u4,
    odd: u4,
};

comptime {
    std.debug.assert(@sizeOf(PagePairOrders) == 1);
}

const NUM_ORDERS = 11;
const ORDERS = blk: {
    var arr: [NUM_ORDERS]usize = undefined;
    for (0..NUM_ORDERS) |i| {
        arr[i] = (1 << i) * PAGE_SIZE;
    }
    break :blk arr;
};

pub const BuddyAllocator = struct {
    start_addr: usize,
    end_addr: usize,
    /// Not a backing allocator, this is only used to allocate and free the page struct array
    allocator: *std.mem.Allocator,
    page_pair_orders: []PagePairOrders,
    freelists: [NUM_ORDERS]BitmapFreeList,

    pub fn init(
        self: *BuddyAllocator,
        start_addr: usize,
        end_addr: usize,
        allocator: *std.mem.Allocator,
    ) !void {
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

        self.start_addr = aligned_start;
        self.end_addr = aligned_end;
        self.allocator = allocator;

        const total_bytes = aligned_end - aligned_start;
        const num_pages = total_bytes / PAGE_SIZE;
        const num_pairs = num_pages / 2;

        self.page_pair_orders = try allocator.alloc(PagePairOrders, num_pairs);
        errdefer allocator.free(self.page_pair_orders);

        var current_addr = start_addr;
        var decrement: isize = 10;
        while (decrement >= 0) : (decrement -= 1) {
            const order: usize = @intCast(decrement);
            const block_size = ORDERS[order];

            const num_bits = total_bytes / block_size;
            const initially_free = false;
            self.freelists[order] = try BitmapFreeList.init(
                start_addr,
                block_size,
                num_bits,
                initially_free,
                allocator,
            );
            errdefer self.freelist[order].deinit();

            while (total_bytes - current_addr >= block_size) : (current_addr += block_size) {
                const freelist = self.freelists[order].freelist();
                freelist.setFree(current_addr);

                const page_idx = current_addr / PAGE_SIZE;
                const pair_idx = page_idx / 2;
                const is_odd = page_idx % 2 == 1;

                if (is_odd) {
                    self.page_pair_orders[pair_idx].odd = @intCast(order);
                } else {
                    self.page_pair_orders[pair_idx].even = @intCast(order);
                }
            }

            std.debug.assert(current_addr <= total_bytes);
        }

        std.debug.assert(current_addr == total_bytes);
    }

    pub fn deinit(self: *BuddyAllocator) void {
        self.allocator.free(self.page_pair_orders);
        for (&self.freelists) |*freelist| {
            freelist.deinit();
        }
    }

    // fn recursive merge

    // allocator and interface
};

test "buddy allocator initializes expected pages and orders correctly" {
    const start_addr = 0x400000;
    var total_size: usize = 10 * ORDERS[10];
    const end_addr = start_addr + total_size;
    const skip_order: usize = 5;
    for (0..NUM_ORDERS - 1) |i| {
        if (i == skip_order) continue;
        total_size += ORDERS[i];
    }

    var allocator = std.testing.allocator;
    var buddy: BuddyAllocator = undefined;
    try buddy.init(
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
        const addr = entry.page_index * PAGE_SIZE;
        const pair_idx = entry.page_index / 2;
        const is_odd = entry.page_index % 2 == 1;

        const freelist = buddy.freelists[entry.order].freelist();
        try std.testing.expect(freelist.isFree(addr));

        if (is_odd) {
            try std.testing.expectEqual(entry.order, buddy.page_pair_orders[pair_idx].odd);
        } else {
            try std.testing.expectEqual(entry.order, buddy.page_pair_orders[pair_idx].even);
        }
    }

    const total_pages = total_size / PAGE_SIZE;
    for (0..total_pages) |page_idx| {
        const addr = page_idx * PAGE_SIZE;
        var is_expected = false;
        var expected_order: u4 = 0;

        for (expected) |entry| {
            if (entry.page_index == page_idx) {
                is_expected = true;
                expected_order = entry.order;
                break;
            }
        }

        if (!is_expected) {
            for (0..NUM_ORDERS) |order| {
                const freelist = buddy.freelists[order].freelist();
                try std.testing.expect(!freelist.isFree(addr));
            }
        }
    }
}

test "buddy allocator init fails with failing allocator" {
    var buddy: BuddyAllocator = undefined;
    const start_addr = 0;
    const end_addr = 5 * ORDERS[10];
    var allocator = std.testing.failing_allocator;
    try std.testing.expectError(
        error.OutOfMemory,
        buddy.init(
            start_addr,
            end_addr,
            &allocator,
        ),
    );
}
