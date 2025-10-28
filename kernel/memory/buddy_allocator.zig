//! Buddy allocator managing page-aligned power-of-two blocks.
//!
//! Owns a contiguous address range and sub-divides/coalesces pages across
//! 2^N orders. Backed by a bitmap (free = 1) plus per-order intrusive free
//! lists and a compact per-pair order table for O(1) order lookups.

const bitmap_freelist = @import("bitmap_freelist.zig");
const intrusive_freelist = @import("intrusive_freelist.zig");
const std = @import("std");

/// Page object used only to give the intrusive free list a size/alignment and
/// to act as the allocation unit for the buddy allocator (4 KiB).
pub const Page = struct {
    bytes: [PAGE_SIZE]u8 align(PAGE_SIZE),

    comptime {
        std.debug.assert(@sizeOf(Page) == PAGE_SIZE);
        std.debug.assert(@alignOf(Page) == PAGE_SIZE);
    }
};

/// Per-2-page metadata storing the current order of the even/odd page.
/// Keeps order state in 1 byte per pair.
const PagePairOrders = packed struct {
    even: u4,
    odd: u4,

    comptime {
        std.debug.assert(@sizeOf(PagePairOrders) == 1);
    }
};

/// Return type for `splitAllocation`: a linked-list batch of blocks at a
/// single order, allowing callers to push them back individually later.
const using_popSpecific = true;
const link_to_list = false;
pub const FreeListBatch = intrusive_freelist.IntrusiveFreeList(
    *Page,
    !using_popSpecific,
    link_to_list,
);

/// Bitmap free list backing the page state (1 = free, 0 = allocated).
const using_getNextFree = false;
const BitmapFreeList = bitmap_freelist.BitmapFreeList(using_getNextFree);

/// Per-order intrusive free list of block bases.
const IntrusiveFreeList = intrusive_freelist.IntrusiveFreeList(
    *Page,
    using_popSpecific,
    link_to_list,
);

/// Number of buddy orders supported (0..10 → 1,2,4,...,1024 pages).
const NUM_ORDERS = 11;

/// Size in bytes for each order, indexed by order.
const ORDERS = blk: {
    var arr: [NUM_ORDERS]u64 = undefined;
    for (0..NUM_ORDERS) |i| {
        arr[i] = (1 << i) * PAGE_SIZE;
    }
    break :blk arr;
};

/// Page size in bytes (4 KiB).
const PAGE_SIZE = 4096;

/// Owning allocator for a contiguous, page-aligned address range.
///
/// Does not require a backing allocator for data blocks (only for metadata
/// during initialization). Exposes a `std.mem.Allocator` interface returning
/// page-multiple, power-of-two allocations.
pub const BuddyAllocator = struct {
    /// Start of managed region (inclusive), PAGE_SIZE-aligned.
    start_addr: u64,
    /// End of managed region (exclusive), PAGE_SIZE-aligned.
    end_addr: u64,

    /// Used only to allocate metadata (bitmap + order table) at init time.
    init_allocator: std.mem.Allocator,

    /// Order table (one byte per pair of pages).
    page_pair_orders: []PagePairOrders = undefined,
    /// Free = 1, allocated = 0.
    bitmap: BitmapFreeList = undefined,
    /// Per-order intrusive free lists for block bases.
    freelists: [NUM_ORDERS]IntrusiveFreeList = [_]IntrusiveFreeList{IntrusiveFreeList{}} ** NUM_ORDERS,

    /// Computes the metadata footprint (bytes) needed to manage `[start_addr, end_addr)`,
    /// accounting for the fact that metadata itself consumes pages.
    ///
    /// Arguments:
    /// - `start_addr`: start of candidate region (may be unaligned).
    /// - `end_addr`: end of candidate region (may be unaligned).
    ///
    /// Returns:
    /// - Number of bytes to reserve for metadata so the remaining data region is stable.
    pub fn requiredMemory(
        start_addr: u64,
        end_addr: u64,
    ) u64 {
        const aligned_start = std.mem.alignForward(u64, start_addr, PAGE_SIZE);
        const aligned_end = std.mem.alignBackward(u64, end_addr, PAGE_SIZE);
        std.debug.assert(aligned_end > aligned_start);

        var n_pages = (aligned_end - aligned_start) / PAGE_SIZE;
        var i: u32 = 0;
        const loop_upper_bound = 3;
        while (true) : (i += 1) {
            if (i >= loop_upper_bound) {
                @panic("Non exitting loop!");
            }

            const bitmap_words = (n_pages + bitmap_freelist.WORD_BIT_SIZE - 1) / bitmap_freelist.WORD_BIT_SIZE;
            const bitmap_bytes = bitmap_words * @sizeOf(bitmap_freelist.Word);
            const orders_bytes = (n_pages + 1) / 2;
            const metadata_bytes = std.mem.alignForward(u64, bitmap_bytes + orders_bytes, PAGE_SIZE);

            const n2_pages = (aligned_end - (aligned_start + metadata_bytes)) / PAGE_SIZE;
            if (n_pages == n2_pages) return metadata_bytes;
            n_pages = n2_pages;
        }
    }

    /// Initializes a buddy allocator managing `[start_addr, end_addr)`.
    ///
    /// Arguments:
    /// - `start_addr`: start (rounded up to PAGE_SIZE).
    /// - `end_addr`: end (rounded down to PAGE_SIZE).
    /// - `init_allocator`: used to allocate internal metadata (bitmap/order table).
    ///
    /// Returns:
    /// - A fully initialized `BuddyAllocator` with freelists seeded by descending orders.
    pub fn init(
        start_addr: u64,
        end_addr: u64,
        init_allocator: std.mem.Allocator,
    ) !BuddyAllocator {
        std.debug.assert(end_addr > start_addr);
        const aligned_start = std.mem.alignForward(u64, start_addr, PAGE_SIZE);
        const aligned_end = std.mem.alignBackward(u64, end_addr, PAGE_SIZE);
        std.debug.assert(aligned_end > aligned_start);

        var self: BuddyAllocator = .{
            .start_addr = aligned_start,
            .end_addr = aligned_end,
            .init_allocator = init_allocator,
        };

        const total_bytes = aligned_end - aligned_start;
        const num_pages = total_bytes / PAGE_SIZE;
        const num_pairs = std.math.divCeil(u64, num_pages, 2) catch unreachable;

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
        @memset(self.page_pair_orders, .{
            .even = 0,
            .odd = 0,
        });

        return self;
    }

    pub fn addRegion(
        self: *BuddyAllocator,
        start_addr: u64,
        end_addr: u64,
    ) void {
        std.debug.assert(end_addr > start_addr);
        const aligned_start = std.mem.alignForward(u64, start_addr, PAGE_SIZE);
        const aligned_end = std.mem.alignBackward(u64, end_addr, PAGE_SIZE);
        std.debug.assert(aligned_end > aligned_start);

        var current_addr = aligned_start;
        var current_order: u4 = NUM_ORDERS - 1;
        while (current_order >= 0) {
            const block_size = ORDERS[current_order];
            while (aligned_end - current_addr >= block_size) {
                self.freelists[current_order].push(@ptrFromInt(current_addr));
                self.bitmap.setBit(current_addr, 1);
                self.setOrder(current_addr, current_order);
                current_addr += block_size;
                std.debug.assert(current_addr <= aligned_end);
            }
            if (current_order == 0) break;
            current_order -= 1;
        }
        std.debug.assert(current_addr == aligned_end);
    }

    /// Releases internal metadata buffers (bitmap and order table).
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    pub fn deinit(self: *BuddyAllocator) void {
        self.init_allocator.free(self.page_pair_orders);
        self.bitmap.deinit();
    }

    /// Returns a `std.mem.Allocator` interface backed by this buddy allocator.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    ///
    /// Returns:
    /// - A `std.mem.Allocator` whose `alloc`/`free` map to this buddy allocator.
    ///   `resize` and `remap` are unsupported (trap).
    ///
    /// Notes:
    /// - Allocation sizes must be multiples of PAGE_SIZE; alignment is ignored.
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

    /// Splits a large allocation at `addr` (of order `getOrder(addr)`) into
    /// blocks of `split_order` and returns them as a batch list.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    /// - `addr`: base address of an existing allocation.
    /// - `split_order`: target smaller order to split into (must be < current).
    ///
    /// Returns:
    /// - `FreeListBatch` whose nodes are `*Page` pointers covering the original range.
    pub fn splitAllocation(
        self: *BuddyAllocator,
        addr: u64,
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

    /// Recursively obtains a block base address of `order`, splitting a higher-order
    /// block if necessary.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    /// - `order`: desired order (0..10).
    ///
    /// Returns:
    /// - Base address of an available block, or `null` if none exist.
    fn recursiveSplit(self: *BuddyAllocator, order: u4) ?u64 {
        const addr_ptr = self.freelists[order].pop() orelse {
            if (order == 10) return null;

            const higher = order + 1;
            const recursive_addr = self.recursiveSplit(higher) orelse return null;

            const rel = recursive_addr - self.start_addr;
            const buddy = self.start_addr + (rel ^ ORDERS[order]);

            if (self.start_addr <= buddy and buddy < self.end_addr) {
                self.setOrder(buddy, order);
                self.bitmap.setBit(buddy, 1);
                self.freelists[order].push(@ptrFromInt(buddy));
            }

            self.setOrder(recursive_addr, order);
            return recursive_addr;
        };

        const addr = @intFromPtr(addr_ptr);
        return addr;
    }

    /// Recursively merges a free block with its buddy while possible, returning
    /// the final merged base address and order.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    /// - `addr`: base address of a free block.
    ///
    /// Returns:
    /// - `{ addr, order }` describing the coalesced block that should be enqueued.
    fn recursiveMerge(self: *BuddyAllocator, addr: u64) struct { addr: u64, order: u4 } {
        const order = self.getOrder(addr);
        if (order == 10) return .{ .addr = addr, .order = order };

        const rel = addr - self.start_addr;
        const buddy = self.start_addr + (rel ^ ORDERS[order]);
        const buddy_out_of_bounds = buddy < self.start_addr or buddy >= self.end_addr;

        if (buddy_out_of_bounds) {
            const higher = order + 1;
            const next_rel = rel & ~ORDERS[higher];
            const next_size_addr = self.start_addr + next_rel;
            const next_size_end = next_size_addr + ORDERS[higher];
            const next_size_within_bounds = next_size_addr >= self.start_addr and next_size_end <= self.end_addr;

            if (next_size_within_bounds) {
                self.setOrder(next_size_addr, higher);
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

        const removed = self.freelists[order].popSpecific(@ptrFromInt(buddy));
        std.debug.assert(removed != null);

        const lower_half = @min(addr, buddy);
        const upper_half = @max(addr, buddy);

        self.bitmap.setBit(lower_half, 0);
        self.bitmap.setBit(upper_half, 0);

        const higher = order + 1;
        self.setOrder(lower_half, higher);
        return self.recursiveMerge(lower_half);
    }

    /// Returns the order (0..10) recorded for the page that begins at `addr`.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    /// - `addr`: page-aligned address within the managed region.
    ///
    /// Returns:
    /// - The current order associated with that page base.
    fn getOrder(self: *BuddyAllocator, addr: u64) u4 {
        const page_idx = (addr - self.start_addr) / PAGE_SIZE;
        const pair_idx = page_idx / 2;
        const is_odd = page_idx % 2 == 1;
        if (is_odd) {
            return self.page_pair_orders[pair_idx].odd;
        } else {
            return self.page_pair_orders[pair_idx].even;
        }
    }

    /// Records `order` for the page that begins at `addr`.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    /// - `addr`: page-aligned address within the managed region.
    /// - `order`: value to store (0..10).
    fn setOrder(self: *BuddyAllocator, addr: u64, order: u4) void {
        const page_idx = (addr - self.start_addr) / PAGE_SIZE;
        const pair_idx = page_idx / 2;
        const is_odd = page_idx % 2 == 1;
        if (is_odd) {
            self.page_pair_orders[pair_idx].odd = order;
        } else {
            self.page_pair_orders[pair_idx].even = order;
        }
    }

    /// `std.mem.Allocator.alloc` entry point.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer to the `BuddyAllocator` (provided by vtable).
    /// - `len`: requested size in bytes (must be a multiple of PAGE_SIZE).
    /// - `alignment`: ignored (blocks are page-aligned).
    /// - `ret_addr`: caller return address for diagnostics (unused).
    ///
    /// Returns:
    /// - Pointer to `len` bytes on success, or `null` if no suitable block exists.
    fn alloc(
        ptr: *anyopaque,
        len: u64,
        alignment: std.mem.Alignment,
        ret_addr: u64,
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

    /// `std.mem.Allocator.resize` entry point (unsupported).
    ///
    /// Always traps; the buddy allocator does not support in-place growth/shrink.
    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    /// `std.mem.Allocator.remap` entry point (unsupported).
    ///
    /// Always traps; the buddy allocator does not support remapping.
    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
    ) ?[*]u8 {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    /// `std.mem.Allocator.free` entry point.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer to the `BuddyAllocator` (provided by vtable).
    /// - `buf`: slice previously returned by `alloc`.
    /// - `alignment`: ignored.
    /// - `ret_addr`: caller return address for diagnostics (unused).
    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: u64,
    ) void {
        _ = alignment;
        _ = ret_addr;
        const self: *BuddyAllocator = @alignCast(@ptrCast(ptr));
        const addr = @intFromPtr(buf.ptr);
        const result = self.recursiveMerge(addr);
        self.bitmap.setBit(result.addr, 1);
        self.freelists[result.order].push(@ptrFromInt(result.addr));
    }

    /// Helper map type used in tests to record active allocations:
    /// key = base address, value = `{ size, order }`.
    pub const AllocationMap = std.HashMap(
        u64,
        struct { size: u64, order: u4 },
        std.hash_map.AutoContext(u64),
        std.hash_map.default_max_load_percentage,
    );

    /// Validates the allocator state against recorded allocations.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    /// - `allocations`: map of active allocations keyed by base address.
    ///
    /// Returns:
    /// - `true` if all invariants hold; `false` after logging a diagnostic dump.
    pub fn validateState(self: *BuddyAllocator, allocations: *AllocationMap) bool {
        const Helper = struct {
            fn fail(reason: []const u8, ctx: struct {
                start_addr: u64 = 0,
                end_addr: u64 = 0,
                page_size: u64 = 0,
                order: u64 = 0,
                addr: u64 = 0,
                end: u64 = 0,
                buddy: u64 = 0,
                expected_order: u64 = 0,
                extra_a: u64 = 0,
                extra_b: u64 = 0,
            }) bool {
                std.debug.print(
                    "\n[Buddy Validate Failed]\nreason={s}\nstart={x} end={x} page_size={d}\norder={d} addr={x} end={x} buddy={x} expected_order={d}\nextra_a={x} extra_b={x}\n",
                    .{
                        reason,
                        ctx.start_addr,
                        ctx.end_addr,
                        ctx.page_size,
                        ctx.order,
                        ctx.addr,
                        ctx.end,
                        ctx.buddy,
                        ctx.expected_order,
                        ctx.extra_a,
                        ctx.extra_b,
                    },
                );
                return false;
            }

            fn isAligned(x: u64, a: u64) bool {
                return (x & (a - 1)) == 0;
            }
        };

        const start = self.start_addr;
        const end = self.end_addr;

        if (!(end > start))
            return Helper.fail("end_addr <= start_addr", .{ .start_addr = start, .end_addr = end });
        if (!Helper.isAligned(start, PAGE_SIZE))
            return Helper.fail("start_addr not PAGE_SIZE aligned", .{ .start_addr = start, .page_size = PAGE_SIZE });
        if (!Helper.isAligned(end, PAGE_SIZE))
            return Helper.fail("end_addr not PAGE_SIZE aligned", .{ .end_addr = end, .page_size = PAGE_SIZE });

        // Collect every free block (base -> order) to (a) spot duplicates and
        // (b) let page-scan cheaply verify membership.
        var free_map = std.AutoHashMap(u64, u4).init(self.init_allocator);
        defer free_map.deinit();

        var order: u64 = 0;
        while (order < NUM_ORDERS) : (order += 1) {
            const blk_size = ORDERS[order];
            var node = self.freelists[order].head;

            while (node) |n| {
                const base = @intFromPtr(n);
                const end_addr = base + blk_size;

                if (base < start or end_addr > end)
                    return Helper.fail("free block out of bounds", .{
                        .start_addr = start,
                        .end_addr = end,
                        .order = order,
                        .addr = base,
                        .end = end_addr,
                    });

                if (!Helper.isAligned(base, PAGE_SIZE))
                    return Helper.fail("free block not page aligned", .{
                        .addr = base,
                        .page_size = PAGE_SIZE,
                        .order = order,
                    });

                // Free-list node must reflect "free" in bitmap and order table at the base page.
                if (!self.bitmap.isFree(base))
                    return Helper.fail("bitmap says allocated but in freelist", .{
                        .addr = base,
                        .order = order,
                    });
                if (self.getOrder(base) != order)
                    return Helper.fail("getOrder(base) != freelist order", .{
                        .addr = base,
                        .order = order,
                        .extra_a = self.getOrder(base),
                    });

                // No duplicate base addresses across all freelists.
                if (free_map.contains(base))
                    return Helper.fail("duplicate free node address across freelists", .{
                        .addr = base,
                        .order = order,
                        .extra_a = free_map.get(base).?,
                    });
                free_map.put(base, @intCast(order)) catch
                    return Helper.fail("OOM inserting into free_map", .{ .order = order });

                // Interior pages of a free block must *not* be individually marked free.
                var inner = base + PAGE_SIZE;
                while (inner < end_addr) : (inner += PAGE_SIZE) {
                    if (self.bitmap.isFree(inner))
                        return Helper.fail("interior page of a free block marked free", .{
                            .addr = inner,
                            .order = order,
                            .extra_a = base,
                            .extra_b = end_addr,
                        });
                }

                node = n.next;
            }
        }

        // Page-level scan
        const total_pages = (end - start) / PAGE_SIZE;
        var page_idx: u64 = 0;
        while (page_idx < total_pages) : (page_idx += 1) {
            const addr = start + page_idx * PAGE_SIZE;
            const ord: u64 = self.getOrder(addr);
            const is_free = self.bitmap.isFree(addr);

            if (!is_free) {
                // Not free: either allocated base, interior of a larger allocation,
                // or interior of a free block (which should never be marked free anyway).
                if (allocations.get(addr)) |info| {
                    const num_pages = info.size / PAGE_SIZE;
                    if (num_pages == 0 or (num_pages & (num_pages - 1)) != 0)
                        return Helper.fail("allocation size not power-of-two pages", .{
                            .addr = addr,
                            .extra_a = info.size,
                        });
                    const expected: u64 = @ctz(num_pages);
                    if (ord != expected)
                        return Helper.fail("allocated page order mismatch", .{
                            .addr = addr,
                            .order = ord,
                            .expected_order = expected,
                        });
                }
                continue;
            }

            // Bitmap says free: must not appear in allocations map.
            if (allocations.contains(addr))
                return Helper.fail("bitmap says free but recorded as allocated", .{ .addr = addr, .order = ord });

            // Free page must be present as a freelist base (use free_map from pass 1).
            if (!free_map.contains(addr))
                return Helper.fail("free page not found in freelists", .{ .addr = addr, .order = ord });

            // Buddy coalescing invariant: two free buddies of same order should not coexist.
            if (ord < (NUM_ORDERS - 1)) {
                const size = ORDERS[ord];
                const buddy = start + (((addr - start) ^ size));
                if (!(buddy < start or buddy >= end)) {
                    if (self.bitmap.isFree(buddy) and self.getOrder(buddy) == ord) {
                        return Helper.fail("coalescing missed: both buddies free at same order", .{
                            .addr = addr,
                            .buddy = buddy,
                            .order = ord,
                        });
                    }
                }
            }
        }

        return true;
    }

    /// Test helper: asserts that after trying to allocate `order`, all freelists
    /// at `order` and above are empty (i.e., allocation must fail).
    ///
    /// Arguments:
    /// - `buddy_alloc`: allocator under test.
    /// - `order`: order to check (0..10).
    ///
    /// Errors:
    /// - Returns `error` from `std.testing.expect` if any freelist is non-empty.
    fn checkAllocationFailure(buddy_alloc: *BuddyAllocator, order: u4) !void {
        for (order..NUM_ORDERS) |check_order| {
            try std.testing.expect(buddy_alloc.freelists[check_order].head == null);
        }
    }
};

test "buddy allocator initializes expected pages and orders correctly" {
    const allocator = std.testing.allocator;

    var total_size: u64 = 10 * ORDERS[10];
    const skip_order: u64 = 5;
    for (0..NUM_ORDERS - 1) |i| {
        if (i == skip_order) continue;
        total_size += ORDERS[i];
    }

    const memory = try allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        total_size,
    );
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

    const expected = [_]struct {
        page_index: u64,
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
    const memory = try test_allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        5 * ORDERS[10],
    );
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

    const memory = try allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        ORDERS[1],
    );
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[1];

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

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

    const memory = try allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        ORDERS[1],
    );
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[1];

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

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
    const memory = try test_allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(ORDERS[10]),
        total_size,
    );
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        test_allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

    var allocator = buddy.allocator();
    var allocations = BuddyAllocator.AllocationMap.init(test_allocator);
    defer allocations.deinit();

    try std.testing.expect(buddy.validateState(&allocations));

    const order_10_ptr = try allocator.alloc(u8, ORDERS[10]);
    try allocations.put(@intFromPtr(order_10_ptr.ptr), .{ .size = ORDERS[10], .order = 10 });
    try std.testing.expect(buddy.validateState(&allocations));

    const order_4_ptr = try allocator.alloc(u8, ORDERS[4]);
    const order_4_addr = @intFromPtr(order_4_ptr.ptr);
    try allocations.put(order_4_addr, .{ .size = ORDERS[4], .order = 4 });
    try std.testing.expect(buddy.validateState(&allocations));

    try std.testing.expectEqual(@as(u4, 4), buddy.getOrder(order_4_addr));

    allocator.free(order_4_ptr);
    _ = allocations.remove(order_4_addr);
    try std.testing.expect(buddy.validateState(&allocations));

    try std.testing.expectEqual(@as(u4, 6), buddy.getOrder(order_4_addr));

    allocator.free(order_10_ptr);
    _ = allocations.remove(@intFromPtr(order_10_ptr.ptr));
    try std.testing.expect(buddy.validateState(&allocations));
}

test "split allocation handles order changes correctly" {
    const test_allocator = std.testing.allocator;
    const total_size: u64 = 2 * ORDERS[10];
    const memory = try test_allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        total_size,
    );
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        test_allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

    var allocator = buddy.allocator();

    var allocations = BuddyAllocator.AllocationMap.init(test_allocator);
    defer allocations.deinit();

    var freelist: FreeListBatch = .{};

    const allocation = try allocator.alloc(u8, ORDERS[10]);
    try allocations.put(@intFromPtr(allocation.ptr), .{ .size = ORDERS[10], .order = 10 });
    try std.testing.expect(buddy.validateState(&allocations));

    _ = allocations.remove(@intFromPtr(allocation.ptr));
    var split = buddy.splitAllocation(@intFromPtr(allocation.ptr), 0);
    var count: u64 = 0;
    while (split.pop()) |page| {
        count += 1;
        freelist.push(page);
        try allocations.put(@intFromPtr(page), .{ .size = ORDERS[0], .order = 0 });
    }
    try std.testing.expect(buddy.validateState(&allocations));
    try std.testing.expect(count == 1024);

    while (freelist.pop()) |page| {
        _ = allocations.remove(@intFromPtr(page));
        const page_slice: []u8 = @as([*]u8, @ptrCast(page))[0..PAGE_SIZE];
        allocator.free(page_slice);
        try std.testing.expect(buddy.validateState(&allocations));
    }
}

test "complex allocation and deallocation with state verification" {
    var test_allocator = std.testing.allocator;
    var total_size: u64 = 10 * ORDERS[10];
    const skip_order: u64 = 7;
    for (0..NUM_ORDERS - 1) |i| {
        if (i == skip_order) continue;
        total_size += ORDERS[i];
    }
    const memory = try test_allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        total_size,
    );
    defer test_allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + total_size;

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        test_allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, end_addr);

    var allocator = buddy.allocator();

    var allocations = BuddyAllocator.AllocationMap.init(test_allocator);
    defer allocations.deinit();

    var validations: u64 = 1;
    try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));

    const ptr1 = try allocator.alloc(u8, ORDERS[skip_order]);
    try allocations.put(@intFromPtr(ptr1.ptr), .{ .size = ORDERS[skip_order], .order = skip_order });
    validations = 2;
    try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));

    const ptr2 = try allocator.alloc(u8, ORDERS[4]);
    try allocations.put(@intFromPtr(ptr2.ptr), .{ .size = ORDERS[4], .order = 4 });
    validations = 3;
    try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));

    const ptr3 = try allocator.alloc(u8, ORDERS[1]);
    try allocations.put(@intFromPtr(ptr3.ptr), .{ .size = ORDERS[1], .order = 1 });
    validations = 4;
    try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));

    allocator.free(ptr1);
    _ = allocations.remove(@intFromPtr(ptr1.ptr));
    validations = 5;
    try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));

    const ptr4 = try allocator.alloc(u8, ORDERS[6]);
    try allocations.put(@intFromPtr(ptr4.ptr), .{ .size = ORDERS[6], .order = 6 });
    validations = 6;
    try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));

    allocator.free(ptr2);
    _ = allocations.remove(@intFromPtr(ptr2.ptr));
    validations = 7;
    try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));

    allocator.free(ptr3);
    _ = allocations.remove(@intFromPtr(ptr3.ptr));
    validations = 8;
    try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));

    allocator.free(ptr4);
    _ = allocations.remove(@intFromPtr(ptr4.ptr));
    validations = 9;
    try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));

    var failed_allocation = false;
    for (0..100) |i| {
        if (allocator.alloc(u8, ORDERS[8])) |ptr| {
            try allocations.put(@intFromPtr(ptr.ptr), .{ .size = ORDERS[8], .order = 8 });
            validations = 10 + i;
            try std.testing.expect(buddy.validateState(&allocations) and (validations == validations));
        } else |_| {
            failed_allocation = true;
            try buddy.checkAllocationFailure(8);
            break;
        }
    }
    try std.testing.expect(failed_allocation);
}

test "split region logic with buddy allocator" {
    const allocator = std.testing.allocator;

    const memory = try allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(PAGE_SIZE),
        ORDERS[6] + ORDERS[0] + ORDERS[4],
    );
    defer allocator.free(memory);

    const start_addr = @intFromPtr(memory.ptr);
    const end_addr = start_addr + ORDERS[6] + ORDERS[0] + ORDERS[4];

    var buddy = try BuddyAllocator.init(
        start_addr,
        end_addr,
        allocator,
    );
    defer buddy.deinit();

    buddy.addRegion(start_addr, start_addr + ORDERS[6]);
    buddy.addRegion(start_addr + ORDERS[6] + ORDERS[0], start_addr + ORDERS[6] + ORDERS[0] + ORDERS[4]);

    const first_alloc = start_addr;
    const second_alloc = start_addr + ORDERS[6] + ORDERS[0];

    try std.testing.expect(first_alloc + ORDERS[6] != second_alloc);

    var allocations = BuddyAllocator.AllocationMap.init(allocator);
    defer allocations.deinit();

    const order_5_ptr = try buddy.allocator().alloc(u8, ORDERS[5]);
    try allocations.put(@intFromPtr(order_5_ptr.ptr), .{ .size = ORDERS[5], .order = 5 });
    try std.testing.expect(buddy.validateState(&allocations));

    const order_2_ptr = try buddy.allocator().alloc(u8, ORDERS[2]);
    try allocations.put(@intFromPtr(order_2_ptr.ptr), .{ .size = ORDERS[2], .order = 2 });
    try std.testing.expect(buddy.validateState(&allocations));

    try std.testing.expect(@intFromPtr(order_5_ptr.ptr) >= first_alloc);
    try std.testing.expect(@intFromPtr(order_5_ptr.ptr) + ORDERS[5] <= first_alloc + ORDERS[6]);

    try std.testing.expect(@intFromPtr(order_2_ptr.ptr) >= second_alloc);
    try std.testing.expect(@intFromPtr(order_2_ptr.ptr) + ORDERS[2] <= second_alloc + ORDERS[4]);

    try std.testing.expect(buddy.validateState(&allocations));
}
