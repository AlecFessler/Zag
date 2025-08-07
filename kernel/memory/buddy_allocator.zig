const std = @import("std");

const bitmap_freelist = @import("bitmap_freelist.zig");
const intrusive_freelist = @import("intrusive_freelist.zig");

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
pub const Page = struct {
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

const using_popSpecific = true;
const IntrusiveFreeList = intrusive_freelist.IntrusiveFreeList(*Page, using_popSpecific);
const using_getNextFree = false;
const BitmapFreeList = bitmap_freelist.BitmapFreeList(using_getNextFree);

/// Return type for splitAllocation, a linked list of blocks of the requested order
pub const FreeListBatch = intrusive_freelist.IntrusiveFreeList(*Page, !using_popSpecific);

/// Owning allocator. Manages a contiguous address space, does not take a backing allocator, can act as a backing allocator;
pub const BuddyAllocator = struct {
    start_addr: usize,
    end_addr: usize,

    /// Not a backing allocator, this is only used to allocate and free the page orders and bitmap
    init_allocator: std.mem.Allocator,

    page_pair_orders: []PagePairOrders = undefined,
    bitmap: BitmapFreeList = undefined,
    freelists: [NUM_ORDERS]IntrusiveFreeList = [_]IntrusiveFreeList{IntrusiveFreeList{}} ** NUM_ORDERS,

    pub fn init(
        start_addr: usize,
        end_addr: usize,
        init_allocator: std.mem.Allocator,
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

    /// Takes an existing allocation of some order and splits it into
    /// a linked list of smaller order blocks that can be individually
    /// returned to the buddy allocator.
    /// The purpose of this is to save on split merge calls when you want
    /// to allocate a large number of some order of allocations, for example
    /// when the pmm wants to reload a cpu's cache of single pages
    pub fn splitAllocation(
        self: *BuddyAllocator,
        addr: usize,
        split_order: u4,
    ) FreeListBatch {
        const order = self.getOrder(addr);
        std.debug.assert(split_order < order);

        var batch: FreeListBatch = .{};

        var current_addr = addr;
        const end_addr = addr + ORDERS[order];
        const block_size = ORDERS[split_order];
        while (current_addr < end_addr) : (current_addr += block_size) {
            self.setOrder(current_addr, split_order);
            batch.push(@ptrFromInt(current_addr));
        }

        return batch;
    }

    /// Intended to be called by alloc if the current order's freelist
    /// returned null on pop(), and assumes the caller is passing the
    /// order that they want a block returned for
    fn recursiveSplit(self: *BuddyAllocator, order: u4) ?usize {
        std.debug.assert(order < 11);

        const addr_ptr = self.freelists[order].pop() orelse {
            if (order == 10) return null;
            const recursive_addr = self.recursiveSplit(order + 1) orelse return null;

            // since we're splitting a larger block, the buddy must be within bounds
            // as it is the upper half of the block, so there's no need to range check
            const buddy = recursive_addr ^ ORDERS[order];
            if (self.start_addr <= buddy and buddy < self.end_addr) {
                self.setOrder(buddy, order);
                self.bitmap.setBit(buddy, 1);
                self.freelists[order].push(@ptrFromInt(buddy));
            }

            self.setOrder(recursive_addr, order);
            return recursive_addr;
        };

        return @intFromPtr(addr_ptr);
    }

    /// Intended to be called in free every time a block is returned
    /// so that coalescing can be performed if possible
    fn recursiveMerge(self: *BuddyAllocator, addr: usize) struct { addr: usize, order: u4 } {
        const order = self.getOrder(addr);
        if (order == 10) {
            return .{ .addr = addr, .order = order };
        }

        const buddy = addr ^ ORDERS[order];
        const buddy_out_of_bounds = buddy < self.start_addr or buddy >= self.end_addr;
        if (buddy_out_of_bounds) {
            const next_size_addr = addr & ~ORDERS[order + 1];
            const next_size_end = next_size_addr + ORDERS[order + 1];
            const next_size_within_bounds = next_size_addr >= self.start_addr and next_size_end <= self.end_addr;
            if (next_size_within_bounds) {
                self.setOrder(next_size_addr, order + 1);
                return self.recursiveMerge(next_size_addr);
            }

            return .{ .addr = addr, .order = order };
        }

        const is_buddy_free = self.bitmap.isFree(buddy);
        if (!is_buddy_free) {
            return .{ .addr = addr, .order = order };
        }

        const buddy_order = self.getOrder(buddy);
        if (buddy_order != order) {
            return .{ .addr = addr, .order = order };
        }

        _ = self.freelists[order].popSpecific(@ptrFromInt(buddy));

        const lower_half = @min(addr, buddy);
        const upper_half = @max(addr, buddy);

        self.bitmap.setBit(lower_half, 0);
        self.bitmap.setBit(upper_half, 0);

        self.setOrder(lower_half, order + 1);
        return self.recursiveMerge(lower_half);
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
        const order: u4 = @intCast(@ctz(num_pages));
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

/// Helper type for use by test cases
const AllocationMap = std.HashMap(
    usize,
    struct { size: usize, order: u4 },
    std.hash_map.AutoContext(usize),
    std.hash_map.default_max_load_percentage,
);

/// Helper function for use by test cases
fn validateState(
    buddy_alloc: *BuddyAllocator,
    allocations: *AllocationMap,
    validations: usize,
) !void {
    // used to identify which call site a validation failed in during a unit test
    // assuming you add debug print statements to make use of it
    _ = validations;

    const total_pages = (buddy_alloc.end_addr - buddy_alloc.start_addr) / PAGE_SIZE;
    for (0..total_pages) |page_idx| {
        const addr = buddy_alloc.start_addr + page_idx * PAGE_SIZE;
        const order = buddy_alloc.getOrder(addr);
        const is_free = buddy_alloc.bitmap.isFree(addr);

        if (!is_free) {
            // an page may not be free, but may not be allocated either, by being part of a larger block
            if (!allocations.contains(addr)) continue;

            if (allocations.get(addr)) |alloc_info| {
                const num_pages = alloc_info.size / PAGE_SIZE;
                const expected_order: u4 = @intCast(@ctz(num_pages));
                // the order should match what's expected given the size of the allocation
                try std.testing.expect(order == expected_order);
            }
            continue;
        }

        // address should not be allocated if the bitmap says its free
        try std.testing.expect(!allocations.contains(addr));

        const maybe_freelist_head = buddy_alloc.freelists[order].head orelse return error.TestUnexpectedResult;

        var current = maybe_freelist_head;
        var found = @intFromPtr(current) == addr;
        while (current.next) |next| {
            if (found) break;
            found = @intFromPtr(next) == addr;
            current = next;
        }
        try std.testing.expect(found);

        const buddy = addr ^ ORDERS[order];
        if (buddy < buddy_alloc.start_addr or buddy >= buddy_alloc.end_addr) continue;

        const buddy_is_free = buddy_alloc.bitmap.isFree(buddy);
        if (!buddy_is_free) continue;

        if (order == 10) continue;
        const buddy_order = buddy_alloc.getOrder(buddy);
        // if the buddy is free, the order should not match
        // otherwise a merge was missed
        try std.testing.expect(order != buddy_order);
    }
}

/// Helper function for use by test cases
fn checkAllocationFailure(buddy_alloc: *BuddyAllocator, order: u4) !void {
    for (order..NUM_ORDERS) |check_order| {
        try std.testing.expect(buddy_alloc.freelists[check_order].head == null);
    }
}

test "buddy allocator initializes expected pages and orders correctly" {
    const allocator = std.testing.allocator;

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
        allocator,
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
    const allocator = std.testing.failing_allocator;

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
            allocator,
        ),
    );
}

test "recursiveSplit splits larger blocks into smaller ones" {
    const allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(u8, PAGE_SIZE, ORDERS[1]);
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[1];

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        allocator,
    );
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
    const allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(u8, PAGE_SIZE, ORDERS[1]);
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[1];

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        allocator,
    );
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

test "out of bounds buddy handling - fragmentation recovery" {
    var test_allocator = std.testing.allocator;

    const total_size = ORDERS[10] + ORDERS[6];
    const memory = try test_allocator.alignedAlloc(u8, ORDERS[10], total_size);
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        test_allocator,
    );
    defer buddy.deinit();

    var allocator = buddy.allocator();
    var allocations = AllocationMap.init(test_allocator);
    defer allocations.deinit();

    try validateState(&buddy, &allocations, 0);

    const order_10_ptr = try allocator.alloc(u8, ORDERS[10]);
    try allocations.put(@intFromPtr(order_10_ptr.ptr), .{ .size = ORDERS[10], .order = 10 });
    try validateState(&buddy, &allocations, 1);

    const order_4_ptr = try allocator.alloc(u8, ORDERS[4]);
    const order_4_addr = @intFromPtr(order_4_ptr.ptr);
    try allocations.put(order_4_addr, .{ .size = ORDERS[4], .order = 4 });
    try validateState(&buddy, &allocations, 2);

    try std.testing.expectEqual(@as(u4, 4), buddy.getOrder(order_4_addr));

    allocator.free(order_4_ptr);
    _ = allocations.remove(order_4_addr);
    try validateState(&buddy, &allocations, 3);

    try std.testing.expectEqual(@as(u4, 6), buddy.getOrder(order_4_addr));

    allocator.free(order_10_ptr);
    _ = allocations.remove(@intFromPtr(order_10_ptr.ptr));
    try validateState(&buddy, &allocations, 4);
}

test "split allocation handles order changes correctly" {
    const test_allocator = std.testing.allocator;
    const total_size: usize = 2 * ORDERS[10];
    const memory = try test_allocator.alignedAlloc(u8, PAGE_SIZE, total_size);
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        test_allocator,
    );
    defer buddy.deinit();

    var allocator = buddy.allocator();

    var allocations = AllocationMap.init(test_allocator);
    defer allocations.deinit();

    var freelist: FreeListBatch = .{};

    const allocation = try allocator.alloc(u8, ORDERS[10]);
    try allocations.put(@intFromPtr(allocation.ptr), .{ .size = ORDERS[10], .order = 10 });
    try validateState(&buddy, &allocations, 1);

    _ = allocations.remove(@intFromPtr(allocation.ptr));
    var split = buddy.splitAllocation(@intFromPtr(allocation.ptr), 0);
    var count: usize = 0;
    while (split.pop()) |page| {
        count += 1;
        freelist.push(page);
        try allocations.put(@intFromPtr(page), .{ .size = ORDERS[0], .order = 0 });
    }
    try validateState(&buddy, &allocations, 2);
    try std.testing.expect(count == 1024);

    while (freelist.pop()) |page| {
        _ = allocations.remove(@intFromPtr(page));
        const page_slice: []u8 = @as([*]u8, @ptrCast(page))[0..PAGE_SIZE];
        allocator.free(page_slice);
        try validateState(&buddy, &allocations, 3);
    }
}

test "complex allocation and deallocation with state verification" {
    var test_allocator = std.testing.allocator;
    var total_size: usize = 10 * ORDERS[10];
    const skip_order: usize = 7;
    for (0..NUM_ORDERS - 1) |i| {
        if (i == skip_order) continue;
        total_size += ORDERS[i];
    }
    const memory = try test_allocator.alignedAlloc(u8, PAGE_SIZE, total_size);
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        test_allocator,
    );
    defer buddy.deinit();

    var allocator = buddy.allocator();

    var allocations = AllocationMap.init(test_allocator);
    defer allocations.deinit();

    //NOTE: Manually increment validations by 1 for each call to make it searchable

    var validations: usize = 1;
    try validateState(&buddy, &allocations, validations);

    const ptr1 = try allocator.alloc(u8, ORDERS[skip_order]);
    try allocations.put(@intFromPtr(ptr1.ptr), .{ .size = ORDERS[skip_order], .order = skip_order });
    validations = 2;
    try validateState(&buddy, &allocations, validations);

    const ptr2 = try allocator.alloc(u8, ORDERS[4]);
    try allocations.put(@intFromPtr(ptr2.ptr), .{ .size = ORDERS[4], .order = 4 });
    validations = 3;
    try validateState(&buddy, &allocations, validations);

    const ptr3 = try allocator.alloc(u8, ORDERS[1]);
    try allocations.put(@intFromPtr(ptr3.ptr), .{ .size = ORDERS[1], .order = 1 });
    validations = 4;
    try validateState(&buddy, &allocations, validations);

    allocator.free(ptr1);
    _ = allocations.remove(@intFromPtr(ptr1.ptr));
    validations = 5;
    try validateState(&buddy, &allocations, validations);

    const ptr4 = try allocator.alloc(u8, ORDERS[6]);
    try allocations.put(@intFromPtr(ptr4.ptr), .{ .size = ORDERS[6], .order = 6 });
    validations = 6;
    try validateState(&buddy, &allocations, validations);

    allocator.free(ptr2);
    _ = allocations.remove(@intFromPtr(ptr2.ptr));
    validations = 7;
    try validateState(&buddy, &allocations, validations);

    allocator.free(ptr3);
    _ = allocations.remove(@intFromPtr(ptr3.ptr));
    validations = 8;
    try validateState(&buddy, &allocations, validations);

    allocator.free(ptr4);
    _ = allocations.remove(@intFromPtr(ptr4.ptr));
    validations = 9;
    try validateState(&buddy, &allocations, validations);

    var failed_allocation = false;
    for (0..100) |i| {
        if (allocator.alloc(u8, ORDERS[8])) |ptr| {
            try allocations.put(@intFromPtr(ptr.ptr), .{ .size = ORDERS[8], .order = 8 });
            validations = 10 + i;
            try validateState(&buddy, &allocations, validations);
        } else |_| {
            failed_allocation = true;
            try checkAllocationFailure(&buddy, 8);
            break;
        }
    }
    try std.testing.expect(failed_allocation);
}
