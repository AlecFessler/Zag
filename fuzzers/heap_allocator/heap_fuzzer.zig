const std = @import("std");

pub const Memory = @import("memory");
const heap_alloc = Memory.HeapAllocator;

const SEED = 0;

const MAX_ALLOC_LEN = 1024;
const HEAP_SIZE = 2 * 1024 * 1024 * 1024;
const ACTIVE_CAP = 16_384;

fn AlignedBlob(comptime N: usize) type {
    return struct {
        bytes: [N]u8 align(N),
    };
}

const AllocType = enum {
    const NUM_TYPES = @typeInfo(AllocType).@"enum".fields.len;

    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    U512,
    U1024,

    fn toString(alloc_type: AllocType) []const u8 {
        return switch (alloc_type) {
            .U8 => "u8",
            .U16 => "u16",
            .U32 => "u32",
            .U64 => "u64",
            .U128 => "u128",
            .U256 => "u256",
            .U512 => "u512",
            .U1024 => "u1024",
        };
    }

    fn allocate(alloc_type: AllocType, len: usize, allocator: std.mem.Allocator) ![*]u8 {
        return switch (alloc_type) {
            .U8 => {
                const mem = try allocator.alloc(u8, len);
                return @ptrCast(mem.ptr);
            },
            .U16 => {
                const mem = try allocator.alloc(u16, len);
                return @ptrCast(mem.ptr);
            },
            .U32 => {
                const mem = try allocator.alloc(u32, len);
                return @ptrCast(mem.ptr);
            },
            .U64 => {
                const mem = try allocator.alloc(u64, len);
                return @ptrCast(mem.ptr);
            },
            .U128 => {
                const mem = try allocator.alloc(AlignedBlob(128), len);
                return @ptrCast(mem.ptr);
            },
            .U256 => {
                const mem = try allocator.alloc(AlignedBlob(256), len);
                return @ptrCast(mem.ptr);
            },
            .U512 => {
                const mem = try allocator.alloc(AlignedBlob(512), len);
                return @ptrCast(mem.ptr);
            },
            .U1024 => {
                const mem = try allocator.alloc(AlignedBlob(1024), len);
                return @ptrCast(mem.ptr);
            },
        };
    }

    fn free(alloc_type: AllocType, addr: usize, len: usize, allocator: std.mem.Allocator) void {
        if (addr == 0 or len == 0) return;

        switch (alloc_type) {
            .U8 => {
                const p: [*]u8 = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U16 => {
                const p: [*]u16 = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U32 => {
                const p: [*]u32 = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U64 => {
                const p: [*]u64 = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U128 => {
                const p: [*]AlignedBlob(128) = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U256 => {
                const p: [*]AlignedBlob(256) = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U512 => {
                const p: [*]AlignedBlob(512) = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U1024 => {
                const p: [*]AlignedBlob(1024) = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
        }
    }
};

const AllocHandle = struct {
    alloc_type: AllocType,
    len: usize,
    addr: usize,
};

const Action = enum {
    alloc,
    free,
};

pub fn main() !void {
    var dbg_allocator = std.heap.DebugAllocator(.{}){};
    const backing_allocator = dbg_allocator.allocator();

    const backing_mem = try backing_allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(@alignOf(u64)),
        HEAP_SIZE,
    );
    defer backing_allocator.free(backing_mem);

    const reserve_start: u48 = @intCast(@intFromPtr(backing_mem.ptr));
    const reserve_end: u48 = @intCast(reserve_start + backing_mem.len);

    var tree_allocator = try heap_alloc.TreeAllocator.init(backing_allocator);
    defer tree_allocator.deinit();

    var heap_allocator = heap_alloc.HeapAllocator.init(
        reserve_start,
        reserve_end,
        &tree_allocator,
    );
    defer heap_allocator.deinit();
    const heap_iface = heap_allocator.allocator();

    var allocations = std.ArrayListUnmanaged(AllocHandle){};
    defer allocations.deinit(backing_allocator);

    var prng = std.Random.DefaultPrng.init(SEED);
    var rand = prng.random();

    for (0..1_000_000) |i| {
        const action: Action = blk: {
            if (allocations.items.len == 0) break :blk Action.alloc;
            if (allocations.items.len == ACTIVE_CAP) break :blk Action.free;
            break :blk @enumFromInt(rand.intRangeAtMost(usize, 0, 1));
        };
        switch (action) {
            .alloc => {
                const alloc_type: AllocType = @enumFromInt(rand.intRangeAtMost(
                    usize,
                    0,
                    AllocType.NUM_TYPES - 1,
                ));
                const alloc_len = rand.intRangeAtMost(
                    usize,
                    1,
                    MAX_ALLOC_LEN,
                );

                const ptr = try AllocType.allocate(
                    alloc_type,
                    alloc_len,
                    heap_iface,
                );
                try allocations.append(backing_allocator, .{
                    .alloc_type = alloc_type,
                    .addr = @intFromPtr(ptr),
                    .len = alloc_len,
                });

                const state = heap_allocator.validateState(backing_allocator);
                std.debug.print("Action {} - Alloc: type {s}, len {}, ptr: {x}, tree count {}, state {}\n", .{
                    i,
                    alloc_type.toString(),
                    alloc_len,
                    @intFromPtr(ptr),
                    heap_allocator.free_tree.count,
                    state,
                });
                std.debug.assert(state);
            },
            .free => {
                const target_idx = rand.intRangeAtMost(
                    usize,
                    0,
                    allocations.items.len - 1,
                );
                const target_handle = allocations.swapRemove(target_idx);

                AllocType.free(
                    target_handle.alloc_type,
                    target_handle.addr,
                    target_handle.len,
                    heap_iface,
                );

                const state = heap_allocator.validateState(backing_allocator);
                std.debug.print("Action {} - Free: type {s}, len {}, addr {x}, tree count {}, state {}\n", .{
                    i,
                    target_handle.alloc_type.toString(),
                    target_handle.len,
                    target_handle.addr,
                    heap_allocator.free_tree.count,
                    state,
                });
                std.debug.assert(state);
            },
        }
    }
}
