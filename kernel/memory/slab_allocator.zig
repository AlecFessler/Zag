const std = @import("std");
const builtin = @import("builtin");

const freelist = @import("free_list.zig");

const DBG = builtin.mode == .Debug;

/// Top level allocator. Requires a backing allocator, does not provide a std.mem.Allocator interface.
pub fn SlabAllocator(
    comptime T: type,
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

    return struct {
        const Self = @This();
        const FreeList = freelist.FreeList(T);

        /// Verifies that all allocated memory is returned before deinit is called on this.
        /// This is necessary because if this were to not be the case, we could handle it by
        /// either tracking and forcibily freeing it, likely leading to a use after free by
        /// whoever made the allocation, or we could deinit anyway, but then it's leaked.
        allocations: if (DBG) i64 else void,

        /// The stack array is intended to allow for things like the vmm's rbt to allocate nodes for initial allocations so the vmm can do the necessary bookkeeping while avoiding a circular dependency where the rbt allocator eventually depends on the vmm itself to serve an allocation.
        stack_array: if (stack_bootstrap) [stack_size]T else void,
        stack_idx: if (stack_bootstrap) usize else void,

        free_list: FreeList,
        backing_allocator: *std.mem.Allocator,

        pub fn init(backing_allocator: *std.mem.Allocator) !Self {
            var self: Self = .{
                .allocations = if (DBG) 0,
                .stack_idx = if (stack_bootstrap) 0,
                .stack_array = if (stack_bootstrap) [_]T{std.mem.zeroes(T)} ** stack_size,
                .free_list = .{
                    .next = null,
                },
                .backing_allocator = backing_allocator,
            };

            if (!stack_bootstrap) {
                for (0..allocation_chunk_size) |_| {
                    const slab = try self.backing_allocator.create(T);
                    self.free_list.push(slab);
                }
            }

            return self;
        }

        pub fn deinit(self: *Self) void {
            if (DBG) std.debug.assert(self.allocations == 0);

            if (stack_bootstrap) {
                const stack_start = @intFromPtr(&self.stack_array[0]);
                const stack_end = stack_start + stack_size * @sizeOf(T);
                while (self.free_list.pop()) |slab| {
                    const slab_addr = @intFromPtr(slab);
                    if (stack_start <= slab_addr and slab_addr < stack_end) {
                        continue;
                    }
                    self.backing_allocator.destroy(slab);
                }
            } else {
                while (self.free_list.pop()) |slab| {
                    self.backing_allocator.destroy(slab);
                }
            }
        }

        pub fn create(self: *Self) !*T {
            if (stack_bootstrap and self.stack_idx < stack_size) {
                const slab = &self.stack_array[self.stack_idx];
                self.stack_idx += 1;
                if (DBG) self.allocations += 1;
                return slab;
            }

            const maybe_slab = self.free_list.pop();
            if (maybe_slab) |slab| {
                if (DBG) self.allocations += 1;
                return slab;
            } else {
                const new_slab = try self.backing_allocator.create(T);
                if (DBG) self.allocations += 1;
                return new_slab;
            }
        }

        pub fn destroy(self: *Self, slab: *T) void {
            if (DBG) self.allocations -= 1;
            if (DBG) std.debug.assert(self.allocations >= 0);
            self.free_list.push(slab);
        }
    };
}

// Large enough for FreeList type requirements
const TestType = struct { data: u64, pad: u64 };

test "stack exhaustion and transition" {
    const stack_size = 4;
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        TestType,
        true,
        stack_size,
        8,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    var stack_objs: [stack_size]*TestType = undefined;
    for (0..stack_size) |i| {
        const obj = try slab_allocator.create();
        obj.* = .{ .data = i, .pad = 0 };
        stack_objs[i] = obj;
    }

    try std.testing.expect(slab_allocator.free_list.next == null);

    const heap_obj = try slab_allocator.create();
    heap_obj.* = .{ .data = 999, .pad = 0 };

    for (stack_objs) |ptr| slab_allocator.destroy(ptr);
    slab_allocator.destroy(heap_obj);
}

test "stack bootstrap stress test" {
    const stack_size = 8;
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        TestType,
        true,
        stack_size,
        16,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

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
        const obj = try slab_allocator.create();
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

    for (objs) |ptr| slab_allocator.destroy(ptr);
}

test "allocation failure with exhausted stack" {
    const stack_size = 3;
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        TestType,
        true,
        stack_size,
        8,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    var stack_objs: [stack_size]*TestType = undefined;
    for (0..stack_size) |i| {
        const obj = try slab_allocator.create();
        stack_objs[i] = obj;
    }

    var failing_allocator = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var failing_alloc = failing_allocator.allocator();
    slab_allocator.backing_allocator = &failing_alloc;

    const result = slab_allocator.create();
    try std.testing.expect(result == error.OutOfMemory);

    slab_allocator.backing_allocator = &test_allocator;

    for (stack_objs) |ptr| slab_allocator.destroy(ptr);
}

test "basic create destroy cycle" {
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        TestType,
        false,
        0,
        16,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    const obj1 = try slab_allocator.create();
    obj1.* = .{ .data = 42, .pad = 0 };

    const obj2 = try slab_allocator.create();
    obj2.* = .{ .data = 84, .pad = 0 };

    try std.testing.expect(obj1.data == 42);
    try std.testing.expect(obj2.data == 84);

    slab_allocator.destroy(obj1);
    slab_allocator.destroy(obj2);

    const obj3 = try slab_allocator.create();
    const obj4 = try slab_allocator.create();

    try std.testing.expect(obj3 == obj2);
    try std.testing.expect(obj4 == obj1);

    slab_allocator.destroy(obj3);
    slab_allocator.destroy(obj4);
}

test "initial freelist population" {
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        TestType,
        false,
        0,
        5,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    var objs: [6]*TestType = undefined;

    for (0..5) |i| {
        const obj = try slab_allocator.create();
        obj.* = .{ .data = i, .pad = 0 };
        objs[i] = obj;
    }

    try std.testing.expect(slab_allocator.free_list.next == null);

    objs[5] = try slab_allocator.create();
    objs[5].* = .{ .data = 999, .pad = 0 };

    for (objs) |ptr| slab_allocator.destroy(ptr);
}

test "memory leak detection" {
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        TestType,
        false,
        0,
        32,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    var objs: [200]*TestType = undefined;
    for (0..200) |i| {
        const obj = try slab_allocator.create();
        obj.* = .{ .data = i, .pad = 0 };
        objs[i] = obj;
        try std.testing.expect(obj.data == i);
    }

    for (objs) |ptr| slab_allocator.destroy(ptr);
}
