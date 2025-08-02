const std = @import("std");
const builtin = @import("builtin");

const fl = @import("intrusive_freelist.zig");

const DBG = builtin.mode == .Debug;

/// Top level allocator. Requires a backing allocator, does not provide a std.mem.Allocator interface.
pub fn SlabAllocator(
    comptime T: type,
    comptime FreeList: type,
    comptime stack_bootstrap: bool,
    comptime stack_size: usize,
    comptime allocation_chunk_size: usize,
) type {
    if (stack_bootstrap) {
        std.debug.assert(stack_size > 0);
    } else {
        std.debug.assert(stack_size == 0);
    }
    std.debug.assert(allocation_chunk_size > 0);

    // Creates a linked list storing the base and length of all
    // slab slice allocations made so deinit can free them correctly
    const AllocHeader = struct {
        const Self = @This();
        ptr: [*]T,
        len: usize,
        next: ?*Self,
    };

    return struct {
        const Self = @This();

        /// Verifies that all allocated memory is returned before deinit is called on this.
        /// This is necessary because if this were to not be the case, we could handle it by
        /// either tracking and forcibily freeing it, likely leading to a use after free by
        /// whoever made the allocation, or we could deinit anyway, but then it's leaked.
        allocations: if (DBG) i64 else void,

        backing_allocator: *std.mem.Allocator,

        /// The stack array is intended to allow for things like the vmm's rbt to allocate nodes for initial allocations so the vmm can do the necessary bookkeeping while avoiding a circular dependency where the rbt allocator eventually depends on the vmm itself to serve an allocation.
        stack_array: if (stack_bootstrap) [stack_size]T else void,
        stack_idx: if (stack_bootstrap) usize else void,

        freelist: FreeList,

        /// Stores a header for every allocation permanently so they can be individually tracked and freed in deinit
        alloc_headers: ?*AllocHeader = null,

        pub fn init(
            freelist: FreeList,
            backing_allocator: *std.mem.Allocator,
        ) !Self {
            var self: Self = .{
                .allocations = if (DBG) 0,

                .stack_array = if (stack_bootstrap) [_]T{std.mem.zeroes(T)} ** stack_size,
                .stack_idx = if (stack_bootstrap) 0,

                .backing_allocator = backing_allocator,
                .freelist = freelist,
            };

            if (!stack_bootstrap) {
                const slice = try self.backing_allocator.alloc(T, allocation_chunk_size);
                errdefer self.backing_allocator.free(slice);
                for (slice) |*slab| {
                    self.freelist.setFree(slab);
                }

                const alloc_header = try self.backing_allocator.create(AllocHeader);
                alloc_header.ptr = slice.ptr;
                alloc_header.len = slice.len;
                alloc_header.next = self.alloc_headers;
                self.alloc_headers = alloc_header;
            }

            return self;
        }

        pub fn deinit(self: *Self) void {
            if (DBG) std.debug.assert(self.allocations == 0);

            while (self.alloc_headers) |alloc_header| {
                self.alloc_headers = alloc_header.next;
                const slice = alloc_header.ptr[0..alloc_header.len];
                self.backing_allocator.free(slice);
                self.backing_allocator.destroy(alloc_header);
            }
        }

        pub fn allocator(self: *Self) std.mem.Allocator {
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

            std.debug.assert(alignment.toByteUnits() == @as(usize, @intCast(@alignOf(T))));
            std.debug.assert(len == @as(usize, @intCast(@sizeOf(T))));

            const self: *Self = @alignCast(@ptrCast(ptr));

            if (stack_bootstrap and self.stack_idx < stack_size) {
                const slab = &self.stack_array[self.stack_idx];
                self.stack_idx += 1;
                if (DBG) self.allocations += 1;
                return @ptrCast(slab);
            }

            const maybe_slab = self.freelist.getNextFree();
            if (maybe_slab) |slab| {
                if (DBG) self.allocations += 1;
                return @ptrCast(slab);
            } else {
                const slice = self.backing_allocator.alloc(T, allocation_chunk_size) catch return null;

                const alloc_header = self.backing_allocator.create(AllocHeader) catch {
                    self.backing_allocator.free(slice);
                    return null;
                };
                alloc_header.ptr = slice.ptr;
                alloc_header.len = slice.len;
                alloc_header.next = self.alloc_headers;
                self.alloc_headers = alloc_header;

                const new_slab = &slice[0];
                for (slice[1..]) |*slab| {
                    self.freelist.setFree(slab);
                }

                if (DBG) self.allocations += 1;
                return @ptrCast(new_slab);
            }
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
            return false;
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
            return null;
        }

        fn free(
            ptr: *anyopaque,
            buf: []u8,
            alignment: std.mem.Alignment,
            ret_addr: usize,
        ) void {
            _ = alignment;
            _ = ret_addr;
            const self: *Self = @alignCast(@ptrCast(ptr));
            const slab: *T = @alignCast(@ptrCast(buf.ptr));

            if (DBG) self.allocations -= 1;
            if (DBG) std.debug.assert(self.allocations >= 0);

            self.freelist.setFree(slab);
        }
    };
}

// Large enough for StackFreeList type requirements
const TestType = struct { data: u64, pad: u64 };

test "stack exhaustion and transition" {
    const IntrusiveFreeList = fl.IntrusiveFreeList(*TestType);
    const FreeList = IntrusiveFreeList.FreeList;
    var freelist: IntrusiveFreeList = .{};

    const stack_bootstrap = true;
    const stack_size = 4;
    const allocation_chunk_size = 8;

    var test_allocator = std.testing.allocator;
    const freelist_iface = freelist.freelist();

    var slab_allocator = try SlabAllocator(
        TestType,
        FreeList,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(
        freelist_iface,
        &test_allocator,
    );
    defer slab_allocator.deinit();
    const allocator = slab_allocator.allocator();

    var stack_objs: [stack_size]*TestType = undefined;
    for (0..stack_size) |i| {
        const obj = try allocator.create(TestType);
        obj.* = .{ .data = i, .pad = 0 };
        stack_objs[i] = obj;
    }

    const heap_obj = try allocator.create(TestType);
    heap_obj.* = .{ .data = 999, .pad = 0 };

    for (stack_objs) |ptr| allocator.destroy(ptr);
    allocator.destroy(heap_obj);
}

test "stack bootstrap stress test" {
    const IntrusiveFreeList = fl.IntrusiveFreeList(*TestType);
    const FreeList = IntrusiveFreeList.FreeList;
    var freelist: IntrusiveFreeList = .{};

    const stack_bootstrap = true;
    const stack_size = 4;
    const allocation_chunk_size = 16;

    var test_allocator = std.testing.allocator;
    const freelist_iface = freelist.freelist();

    var slab_allocator = try SlabAllocator(
        TestType,
        FreeList,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(
        freelist_iface,
        &test_allocator,
    );
    defer slab_allocator.deinit();
    const allocator = slab_allocator.allocator();

    const stack_start = @intFromPtr(&slab_allocator.stack_array[0]);
    const stack_end = stack_start + stack_size * @sizeOf(TestType);
    const isFromStack = struct {
        fn check(ptr: *TestType, start: usize, end: usize) bool {
            const addr = @intFromPtr(ptr);
            return addr >= start and addr < end;
        }
    }.check;

    var stack_count: usize = 0;
    var heap_count: usize = 0;
    var objs: [100]*TestType = undefined;

    for (0..100) |i| {
        const obj = try allocator.create(TestType);
        obj.* = .{ .data = i, .pad = 0 };
        objs[i] = obj;

        if (isFromStack(obj, stack_start, stack_end)) {
            stack_count += 1;
        } else {
            heap_count += 1;
        }
    }

    try std.testing.expect(stack_count == stack_size);
    try std.testing.expect(heap_count == 100 - stack_size);

    for (objs) |ptr| allocator.destroy(ptr);
}

test "allocation failure with exhausted stack" {
    const IntrusiveFreeList = fl.IntrusiveFreeList(*TestType);
    const FreeList = IntrusiveFreeList.FreeList;
    var freelist: IntrusiveFreeList = .{};

    const stack_bootstrap = true;
    const stack_size = 3;
    const allocation_chunk_size = 8;

    var test_allocator = std.testing.allocator;
    const freelist_iface = freelist.freelist();

    var slab_allocator = try SlabAllocator(
        TestType,
        FreeList,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(
        freelist_iface,
        &test_allocator,
    );
    defer slab_allocator.deinit();
    const allocator = slab_allocator.allocator();

    var stack_objs: [stack_size]*TestType = undefined;
    for (0..stack_size) |i| {
        const obj = try allocator.create(TestType);
        stack_objs[i] = obj;
    }

    var failing_allocator = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var failing_alloc = failing_allocator.allocator();
    slab_allocator.backing_allocator = &failing_alloc;

    const result = allocator.create(TestType);
    try std.testing.expect(result == error.OutOfMemory);

    slab_allocator.backing_allocator = &test_allocator;

    for (stack_objs) |ptr| allocator.destroy(ptr);
}

test "basic create destroy cycle" {
    const IntrusiveFreeList = fl.IntrusiveFreeList(*TestType);
    const FreeList = IntrusiveFreeList.FreeList;
    var freelist: IntrusiveFreeList = .{};

    const stack_bootstrap = false;
    const stack_size = 0;
    const allocation_chunk_size = 16;

    var test_allocator = std.testing.allocator;
    const freelist_iface = freelist.freelist();

    var slab_allocator = try SlabAllocator(
        TestType,
        FreeList,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(
        freelist_iface,
        &test_allocator,
    );
    defer slab_allocator.deinit();
    const allocator = slab_allocator.allocator();

    const obj1 = try allocator.create(TestType);
    obj1.* = .{ .data = 42, .pad = 0 };

    const obj2 = try allocator.create(TestType);
    obj2.* = .{ .data = 84, .pad = 0 };

    try std.testing.expect(obj1.data == 42);
    try std.testing.expect(obj2.data == 84);

    allocator.destroy(obj1);
    allocator.destroy(obj2);

    const obj3 = try allocator.create(TestType);
    const obj4 = try allocator.create(TestType);

    try std.testing.expect(obj3 == obj2);
    try std.testing.expect(obj4 == obj1);

    allocator.destroy(obj3);
    allocator.destroy(obj4);
}

test "initial freelist population" {
    const IntrusiveFreeList = fl.IntrusiveFreeList(*TestType);
    const FreeList = IntrusiveFreeList.FreeList;
    var freelist: IntrusiveFreeList = .{};

    const stack_bootstrap = false;
    const stack_size = 0;
    const allocation_chunk_size = 5;

    var test_allocator = std.testing.allocator;
    const freelist_iface = freelist.freelist();

    var slab_allocator = try SlabAllocator(
        TestType,
        FreeList,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(
        freelist_iface,
        &test_allocator,
    );
    defer slab_allocator.deinit();
    const allocator = slab_allocator.allocator();

    var objs: [6]*TestType = undefined;

    for (0..5) |i| {
        const obj = try allocator.create(TestType);
        obj.* = .{ .data = i, .pad = 0 };
        objs[i] = obj;
    }

    objs[5] = try allocator.create(TestType);
    objs[5].* = .{ .data = 999, .pad = 0 };

    for (objs) |ptr| allocator.destroy(ptr);
}

test "memory leak detection" {
    const IntrusiveFreeList = fl.IntrusiveFreeList(*TestType);
    const FreeList = IntrusiveFreeList.FreeList;
    var freelist: IntrusiveFreeList = .{};

    const stack_bootstrap = false;
    const stack_size = 0;
    const allocation_chunk_size = 32;

    var test_allocator = std.testing.allocator;
    const freelist_iface = freelist.freelist();

    var slab_allocator = try SlabAllocator(
        TestType,
        FreeList,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(
        freelist_iface,
        &test_allocator,
    );
    defer slab_allocator.deinit();
    const allocator = slab_allocator.allocator();

    var objs: [200]*TestType = undefined;
    for (0..200) |i| {
        const obj = try allocator.create(TestType);
        obj.* = .{ .data = i, .pad = 0 };
        objs[i] = obj;
        try std.testing.expect(obj.data == i);
    }

    for (objs) |ptr| allocator.destroy(ptr);
}
