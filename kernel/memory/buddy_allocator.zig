const std = @import("std");

const array_free_list = @import("array_free_list.zig");
const paging = @import("../arch/x86_64/paging.zig");
const PageSize = paging.PageSize;

const FreeList = array_free_list.ArrayFreeList(usize);

const Page = packed struct {
    available: bool,
    order: u7,
};

comptime {
    std.debug.assert(@sizeOf(Page) == 1);
}

const NUM_ORDERS = 11;
const ORDERS = .{
    1 << 0 * PageSize.Page4k,
    1 << 1 * PageSize.Page4k,
    1 << 2 * PageSize.Page4k,
    1 << 3 * PageSize.Page4k,
    1 << 4 * PageSize.Page4k,
    1 << 5 * PageSize.Page4k,
    1 << 6 * PageSize.Page4k,
    1 << 7 * PageSize.Page4k,
    1 << 8 * PageSize.Page4k,
    1 << 9 * PageSize.Page4k,
    1 << 10 * PageSize.Page4k,
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
    ) !BuddyAllocator {
        std.debug.assert(end_addr > start_addr);

        const aligned_start = std.mem.alignForward(
            usize,
            start_addr,
            @intFromEnum(PageSize.Page4K),
        );
        const aligned_end = std.mem.alignBackward(
            usize,
            end_addr,
            @intFromEnum(PageSize.Page4K),
        );

        std.debug.assert(aligned_end > aligned_start);

        self.start_addr = aligned_start;
        self.end_addr = aligned_end;
        self.allocator = allocator;

        const num_bytes = aligned_end - aligned_start;
        const page_size = @intFromEnum(PageSize.Page4K);
        const num_pages = num_bytes / page_size;

        self.pages = try allocator.alloc(Page, num_pages);
        errdefer allocator.free(self.pages);
        @memset(self.pages, 0);

        // initializing with as many order 10 blocks as possible
        var leftover_bytes = num_bytes % ORDERS[10];
        const boundary = num_bytes - leftover_bytes;
        const order_slices_size = boundary / page_size;

        var current_page: usize = 0;
        var current_addr: usize = 0;
        for (10..-1) |order| {
            var alloc_size = order_slices_size;
            const block_size = ORDERS[@intCast(order)];

            // at some point in this loop we need to iterate over the pages covered
            // by the address range this order spans and initialize them as available
            // as well as with their respective order

            // order 10 blocks can go in the freelist right here

            // check if this order needs more slots than order 10 did due to leftover bytes.
            // order 10 will not enter this branch because leftover bytes is defined
            // as total bytes mod order 10 block size
            if (leftover_bytes > block_size) {
                const num_extra = leftover_bytes / block_size;
                alloc_size += num_extra;

                // it makes sense to push non order 10 blocks to freelist here since num_extra is how many there will be for this order

                leftover_bytes = leftover_bytes % block_size;
            }

            // ensure we didn't go beyond the expected bounds for bytes and pages
            std.debug.assert(current_page <= num_pages);
            std.debug.assert(current_addr <= num_bytes);
        }

        // ensure we accounted for all bytes and pages
        std.debug.assert(current_page == num_pages);
        std.debug.assert(current_addr == num_bytes);
    }

    pub fn deinit() void {}

    // fn recursive split

    // fn recursive merge

    // allocator and interface
};
