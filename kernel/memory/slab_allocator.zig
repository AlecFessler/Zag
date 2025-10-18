//! Slab allocator for fixed-size objects.
//!
//! Factory that produces a type-specialized allocator for `T`. Allocates slabs
//! in chunks from a backing allocator and hands out individual `T` objects via
//! an intrusive freelist. Optionally supports a small bootstrap stack so code
//! that depends on this allocator can allocate nodes before the general heap
//! is ready.
//!
//! Exposes a `std.mem.Allocator` interface that only supports exact-size,
//! exact-alignment allocations for `T`; `resize`/`remap` are unsupported.

const builtin = @import("builtin");
const intrusive_freelist = @import("intrusive_freelist.zig");
const std = @import("std");

const DBG = builtin.mode == .Debug;

/// Top-level slab allocator factory. Requires a backing allocator; returns a
/// concrete allocator `type` specialized for `T`.
///
/// Compile-time parameters:
/// - `T`: element type managed by the slab.
/// - `stack_bootstrap`: when true, preallocates a fixed in-struct stack of `T`
///   for early allocations without touching the backing allocator.
/// - `stack_size`: number of `T` elements in the bootstrap stack (0 if disabled).
/// - `allocation_chunk_size`: number of `T` elements to request per slab chunk.
///
/// Returns:
/// - A concrete allocator `type` with `init/deinit/allocator()` and vtable.
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

    // Linked list of slab chunks we allocated so deinit can free them.
    const AllocHeader = struct {
        const Self = @This();
        ptr: [*]T,
        len: usize,
        next: ?*Self,
    };

    return struct {
        const Self = @This();
        const using_popSpecific = false;
        const link_to_list = false;
        const IntrusiveFreeList = intrusive_freelist.IntrusiveFreeList(*T, using_popSpecific, link_to_list);

        /// In debug builds, track outstanding allocations to ensure all are freed
        /// before `deinit` (prevents silent leaks or UAF after forced free).
        allocations: if (DBG) i64 else void,

        /// Allocator used to allocate and free slab chunks and headers.
        backing_allocator: std.mem.Allocator,

        /// Bootstrap stack to break allocator dependency cycles (optional).
        /// Useful when `T` is, e.g., a tree node type needed to bring up VMM.
        stack_array: if (stack_bootstrap) [stack_size]T else void,
        stack_idx: if (stack_bootstrap) usize else void,

        /// Free list of available `T` objects (intrusive nodes live in the objects).
        freelist: IntrusiveFreeList = .{},

        /// Permanent list of all slab chunks we've ever allocated.
        alloc_headers: ?*AllocHeader = null,

        /// Initializes a slab allocator that draws chunks from `backing_allocator`.
        ///
        /// Arguments:
        /// - `backing_allocator`: allocator to obtain/finalize slab chunks.
        ///
        /// Returns:
        /// - `Self` on success, with freelist pre-seeded (unless stack bootstrap).
        pub fn init(
            backing_allocator: std.mem.Allocator,
        ) !Self {
            var self: Self = .{
                .allocations = if (DBG) 0,
                .stack_array = if (stack_bootstrap) [_]T{std.mem.zeroes(T)} ** stack_size,
                .stack_idx = if (stack_bootstrap) 0,
                .backing_allocator = backing_allocator,
            };

            if (!stack_bootstrap) {
                const slice = try self.backing_allocator.alloc(T, allocation_chunk_size);
                errdefer self.backing_allocator.free(slice);
                for (slice) |*slab| {
                    self.freelist.push(slab);
                }

                const alloc_header = try self.backing_allocator.create(AllocHeader);
                alloc_header.* = .{
                    .ptr = slice.ptr,
                    .len = slice.len,
                    .next = self.alloc_headers,
                };
                self.alloc_headers = alloc_header;
            }

            return self;
        }

        /// Releases all slab chunks previously obtained from the backing allocator.
        ///
        /// Arguments:
        /// - `self`: allocator instance.
        ///
        /// Notes:
        /// - In Debug, asserts that all outstanding items were returned (`allocations == 0`).
        pub fn deinit(self: *Self) void {
            if (DBG) std.debug.assert(self.allocations == 0);

            while (self.alloc_headers) |alloc_header| {
                self.alloc_headers = alloc_header.next;
                const slice = alloc_header.ptr[0..alloc_header.len];
                self.backing_allocator.free(slice);
                self.backing_allocator.destroy(alloc_header);
            }
        }

        /// Exposes this slab as a `std.mem.Allocator`.
        ///
        /// Returns:
        /// - A `std.mem.Allocator` whose vtable allocates/frees single `T` objects.
        ///   `resize` and `remap` are unsupported (return false/null).
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

        /// `std.mem.Allocator.alloc` entry point.
        ///
        /// Behavior:
        /// - Requires `alignment == @alignOf(T)` and `len == @sizeOf(T)`.
        /// - Prefer bootstrap stack (if enabled) → freelist → allocate new chunk.
        ///
        /// Arguments:
        /// - `ptr`: opaque pointer to `Self`.
        /// - `len`: requested size (must equal `@sizeOf(T)`).
        /// - `alignment`: required alignment (must equal `@alignOf(T)`).
        /// - `ret_addr`: caller return address (unused).
        ///
        /// Returns:
        /// - Pointer to a single `T` on success, or `null` on OOM.
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

            const maybe_slab = self.freelist.pop();
            if (maybe_slab) |slab| {
                if (DBG) self.allocations += 1;
                return @ptrCast(slab);
            } else {
                const slice = self.backing_allocator.alloc(T, allocation_chunk_size) catch return null;

                const alloc_header = self.backing_allocator.create(AllocHeader) catch {
                    self.backing_allocator.free(slice);
                    return null;
                };
                alloc_header.* = .{
                    .ptr = slice.ptr,
                    .len = slice.len,
                    .next = self.alloc_headers,
                };
                self.alloc_headers = alloc_header;

                const new_slab = &slice[0];
                for (slice[1..]) |*slab| {
                    self.freelist.push(slab);
                }

                if (DBG) self.allocations += 1;
                return @ptrCast(new_slab);
            }
        }

        /// `std.mem.Allocator.resize` entry point (unsupported).
        ///
        /// Returns:
        /// - Always `false`.
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

        /// `std.mem.Allocator.remap` entry point (unsupported).
        ///
        /// Returns:
        /// - Always `null`.
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

        /// `std.mem.Allocator.free` entry point.
        ///
        /// Arguments:
        /// - `ptr`: opaque pointer to `Self`.
        /// - `buf`: slice whose `ptr` is a previously returned `T*`.
        /// - `alignment`: alignment (ignored, validated on alloc).
        /// - `ret_addr`: caller return address (unused).
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

            self.freelist.push(slab);
        }
    };
}

const TestType = struct { data: u64, pad: u64 };

test "stack exhaustion and transition" {
    const stack_bootstrap = true;
    const stack_size = 4;
    const allocation_chunk_size = 8;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(test_allocator);
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
    const stack_bootstrap = true;
    const stack_size = 4;
    const allocation_chunk_size = 16;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(test_allocator);
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
    const stack_bootstrap = true;
    const stack_size = 3;
    const allocation_chunk_size = 8;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(test_allocator);
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
    const failing_alloc = failing_allocator.allocator();
    slab_allocator.backing_allocator = failing_alloc;

    const result = allocator.create(TestType);
    try std.testing.expect(result == error.OutOfMemory);

    slab_allocator.backing_allocator = test_allocator;

    for (stack_objs) |ptr| allocator.destroy(ptr);
}

test "basic create destroy cycle" {
    const stack_bootstrap = false;
    const stack_size = 0;
    const allocation_chunk_size = 16;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(test_allocator);
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

test "memory leak detection" {
    const stack_bootstrap = false;
    const stack_size = 0;
    const allocation_chunk_size = 32;

    const test_allocator = std.testing.allocator;

    var slab_allocator = try SlabAllocator(
        TestType,
        stack_bootstrap,
        stack_size,
        allocation_chunk_size,
    ).init(test_allocator);
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
