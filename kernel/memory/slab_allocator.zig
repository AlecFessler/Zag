const std = @import("std");

const freelist = @import("free_list.zig");

/// Top level allocator. Requires a backing allocator, does not provide a std.mem.Allocator interface.
pub fn SlabAllocator(
    comptime T: type,
    comptime stack_bootstrap: bool,
    comptime stack_size: usize,
    comptime allocation_chunk_size: usize,
) type {
    return struct {
        const Self = @This();
        const FreeList = freelist.FreeList(T);

        /// The stack array is intended to allow for things like the vmm's rbt to allocate nodes for initial allocations so the vmm can do the necessary bookkeeping while avoiding a circular dependency where the rbt allocator eventually depends on the vmm itself to serve an allocation.
        stack_array: [stack_size]T,
        free_list: FreeList,
        backing_allocator: *std.mem.Allocator,

        pub fn init(backing_allocator: *std.mem.Allocator) !Self {
            var self: Self = .{
                .stack_array = undefined,
                .free_list = .{
                    .next = null,
                },
                .backing_allocator = backing_allocator,
            };

            if (stack_bootstrap) {
                std.debug.print("Stack array starts at: {}\n", .{@intFromPtr(&self.stack_array[0])});
                for (&self.stack_array) |*slab| {
                    std.debug.print("Pushing stack slab at: {}\n", .{@intFromPtr(slab)});
                    self.free_list.push(slab);
                }
            } else {
                for (0..allocation_chunk_size) |_| {
                    const slab = try self.backing_allocator.create(T);
                    self.free_list.push(slab);
                }
            }

            return self;
        }

        pub fn deinit(self: *Self) void {
            if (stack_bootstrap) {
                const stack_start = @intFromPtr(&self.stack_array[0]);
                const stack_end = stack_start + stack_size * @sizeOf(T);
                std.debug.print("Stack bounds: {} to {}\n", .{ stack_start, stack_end });

                while (self.free_list.pop()) |slab| {
                    const slab_addr = @intFromPtr(slab);
                    std.debug.print("Checking slab at {}\n", .{slab_addr});

                    if (slab_addr >= stack_start and slab_addr < stack_end) {
                        std.debug.print("Stack slab detected, skipping\n", .{});
                        continue;
                    }
                    std.debug.print("Heap slab, destroying\n", .{});
                    self.backing_allocator.destroy(slab);
                }
            } else {
                while (self.free_list.pop()) |slab| {
                    self.backing_allocator.destroy(slab);
                }
            }
        }

        pub fn create(self: *Self) !*T {
            const maybe_slab = self.free_list.pop();
            if (maybe_slab) |slab| {
                std.debug.print("Returning from freelist: {}\n", .{@intFromPtr(slab)});
                return slab;
            } else {
                const new_slab = try self.backing_allocator.create(T);
                std.debug.print("Created new heap slab: {}\n", .{@intFromPtr(new_slab)});
                return new_slab;
            }
        }

        pub fn destroy(self: *Self, slab: *T) void {
            self.free_list.push(slab);
        }
    };
}

test "basic create destroy cycle" {
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        usize,
        false,
        0,
        16,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    const obj1 = try slab_allocator.create();
    obj1.* = 42;

    const obj2 = try slab_allocator.create();
    obj2.* = 84;

    try std.testing.expect(obj1.* == 42);
    try std.testing.expect(obj2.* == 84);

    slab_allocator.destroy(obj1);
    slab_allocator.destroy(obj2);

    const obj3 = try slab_allocator.create();
    const obj4 = try slab_allocator.create();

    try std.testing.expect(obj3 == obj2);
    try std.testing.expect(obj4 == obj1);

    slab_allocator.destroy(obj3);
    slab_allocator.destroy(obj4);
}

test "stack exhaustion and transition" {
    const stack_size = 4;
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        usize,
        true,
        stack_size,
        8,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    for (0..stack_size) |i| {
        const obj = try slab_allocator.create();
        obj.* = i;
    }

    try std.testing.expect(slab_allocator.free_list.next == null);

    const heap_obj = try slab_allocator.create();
    heap_obj.* = 999;

    slab_allocator.destroy(heap_obj);
}

test "stack bootstrap stress test" {
    const stack_size = 8;
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        usize,
        true,
        stack_size,
        16,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    const stack_start = @intFromPtr(&slab_allocator.stack_array[0]);
    const stack_end = stack_start + stack_size * @sizeOf(usize);
    const isFromStack = struct {
        fn check(ptr: *usize, start: usize, end: usize) bool {
            const addr = @intFromPtr(ptr);
            return addr >= start and addr < end;
        }
    }.check;

    var stack_count: usize = 0;
    var heap_count: usize = 0;

    for (0..100) |i| {
        const obj = try slab_allocator.create();
        obj.* = i;

        if (isFromStack(obj, stack_start, stack_end)) {
            stack_count += 1;
        } else {
            heap_count += 1;
        }
    }

    try std.testing.expect(stack_count == stack_size);
    try std.testing.expect(heap_count == 100 - stack_size);
}

test "allocation failure with exhausted stack" {
    const stack_size = 3;
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        usize,
        true,
        stack_size,
        8,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    for (0..stack_size) |_| {
        _ = try slab_allocator.create();
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
}

test "initial freelist population" {
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        usize,
        false,
        0,
        5,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    for (0..5) |i| {
        const obj = try slab_allocator.create();
        obj.* = i;
    }

    try std.testing.expect(slab_allocator.free_list.next == null);

    const next_obj = try slab_allocator.create();
    next_obj.* = 999;
}

test "memory leak detection" {
    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        usize,
        false,
        0,
        32,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    for (0..200) |i| {
        const obj = try slab_allocator.create();
        obj.* = i;
        try std.testing.expect(obj.* == i);
    }
}

test "different object types" {
    const LargeStruct = struct {
        data: [32]usize,

        fn init(value: usize) @This() {
            return @This(){ .data = [_]usize{value} ** 32 };
        }
    };

    var test_allocator = std.testing.allocator;
    var slab_allocator = try SlabAllocator(
        LargeStruct,
        false,
        0,
        8,
    ).init(&test_allocator);
    defer slab_allocator.deinit();

    const obj1 = try slab_allocator.create();
    obj1.* = LargeStruct.init(42);

    const obj2 = try slab_allocator.create();
    obj2.* = LargeStruct.init(84);

    try std.testing.expect(obj1.data[0] == 42);
    try std.testing.expect(obj1.data[31] == 42);
    try std.testing.expect(obj2.data[0] == 84);
    try std.testing.expect(obj2.data[31] == 84);
}
