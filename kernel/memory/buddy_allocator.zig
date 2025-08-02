const std = @import("std");

const array_free_list = @import("array_free_list.zig");

const PAGE_SIZE = 4096;

const FreeList = array_free_list.ArrayFreeList(usize);

const Page = packed struct {
    available: bool,
    order: u7,
};

comptime {
    std.debug.assert(@sizeOf(Page) == 1);
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
    pages: []Page,
    free_lists: [NUM_ORDERS]FreeList,

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

        self.pages = try allocator.alloc(Page, num_pages);
        errdefer allocator.free(self.pages);
        const zero_init: Page = .{
            .available = false,
            .order = 0,
        };
        @memset(self.pages, zero_init);

        // initializing with as many order 10 blocks as possible
        var leftover_bytes = total_bytes % ORDERS[10];
        const boundary = total_bytes - leftover_bytes;
        const order_slices_size = boundary / PAGE_SIZE;

        var current_addr: usize = 0;
        var decrement: isize = 10;
        while (decrement >= 0) : (decrement -= 1) {
            const order: usize = @intCast(decrement);
            var num_extra: usize = 0;
            const block_size = ORDERS[order];

            if (leftover_bytes > block_size) {
                num_extra = leftover_bytes / block_size;
                leftover_bytes = leftover_bytes % block_size;
            }

            const slice = try allocator.alloc(
                usize,
                order_slices_size + num_extra,
            );
            errdefer allocator.free(slice);
            self.free_lists[order] = FreeList.init(slice);

            while (total_bytes - current_addr >= block_size) : (current_addr += block_size) {
                const idx = current_addr / PAGE_SIZE;
                self.pages[idx] = .{
                    .available = true,
                    .order = @intCast(order),
                };
            }

            std.debug.assert(current_addr <= total_bytes);
        }

        std.debug.assert(current_addr == total_bytes);
    }

    pub fn deinit(self: *BuddyAllocator) void {
        self.allocator.free(self.pages);
        for (&self.free_lists) |*free_list| {
            self.allocator.free(free_list.array);
        }
    }

    fn recursiveSplit(self: *BuddyAllocator, order: u7) ?usize {
        std.debug.assert(order < 11);

        const maybe_addr = self.free_lists[order].pop() orelse blk: {
            if (order == 10) return null;
            break :blk self.recursiveSplit(order + 1);
        };

        if (maybe_addr) |addr| {
            const buddy = addr ^ ORDERS[order];
            const buddy_idx = buddy / PAGE_SIZE;
            self.pages[buddy_idx] = .{
                .available = true,
                .order = order,
            };

            return addr;
        } else return null;
    }

    // fn recursive merge

    // allocator and interface
};

test "buddy allocator initializes expected pages and orders correctly" {
    // create an address space that will have 10 order 10 blocks,
    // and then 1 more block for each order except 5
    var total_size: usize = 10 * ORDERS[10];
    const skip_order: usize = 5;
    for (0..NUM_ORDERS - 1) |i| {
        if (i == skip_order) continue;
        total_size += ORDERS[i];
    }

    const start_addr = 0;
    const end_addr = total_size;
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
        order: u7,
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
        const page = buddy.pages[entry.page_index];
        try std.testing.expect(page.available);
        try std.testing.expectEqual(entry.order, page.order);
    }

    for (buddy.pages, 0..) |page, i| {
        var is_expected = false;
        for (expected) |entry| {
            if (entry.page_index == i) {
                is_expected = true;
                break;
            }
        }
        if (!is_expected) {
            try std.testing.expect(!page.available);
            try std.testing.expectEqual(@as(u7, 0), page.order);
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
