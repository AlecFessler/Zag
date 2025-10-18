const std = @import("std");

const Memory = @import("memory");
const buddy_alloc = Memory.BuddyAllocator;

const PAGE_SIZE = 4096;
const NUM_ORDERS = 11;
const ORDERS = blk: {
    var arr: [NUM_ORDERS]usize = undefined;
    for (0..NUM_ORDERS) |i| arr[i] = (1 << i) * PAGE_SIZE;
    break :blk arr;
};

const SEED = 0;
const ACTIVE_CAP = 16_384;
const ORDER10_BLOCKS = 8;
const POOL_SIZE = ORDER10_BLOCKS * ORDERS[10];

const AllocType = enum {
    const NUM_TYPES = @typeInfo(AllocType).@"enum".fields.len;

    O0,
    O1,
    O2,
    O3,
    O4,
    O5,
    O6,
    O7,
    O8,
    O9,
    O10,

    fn toString(a: AllocType) []const u8 {
        return switch (a) {
            .O0 => "o0",
            .O1 => "o1",
            .O2 => "o2",
            .O3 => "o3",
            .O4 => "o4",
            .O5 => "o5",
            .O6 => "o6",
            .O7 => "o7",
            .O8 => "o8",
            .O9 => "o9",
            .O10 => "o10",
        };
    }

    fn idx(a: AllocType) usize {
        return switch (a) {
            .O0 => 0,
            .O1 => 1,
            .O2 => 2,
            .O3 => 3,
            .O4 => 4,
            .O5 => 5,
            .O6 => 6,
            .O7 => 7,
            .O8 => 8,
            .O9 => 9,
            .O10 => 10,
        };
    }

    fn size(a: AllocType) usize {
        return ORDERS[a.idx()];
    }

    fn allocate(a: AllocType, allocator: std.mem.Allocator) ![*]u8 {
        const mem = try allocator.alloc(u8, a.size());
        return @ptrCast(mem.ptr);
    }

    fn free(a: AllocType, addr: usize, allocator: std.mem.Allocator) void {
        if (addr == 0) return;
        const p: [*]u8 = @ptrFromInt(addr);
        allocator.free(p[0..a.size()]);
    }
};

const AllocHandle = struct {
    alloc_type: AllocType,
    addr: usize,
};

const Action = enum { alloc, free };

pub fn main() !void {
    var dbg_allocator = std.heap.DebugAllocator(.{}){};
    const backing_allocator = dbg_allocator.allocator();

    const backing_mem = try backing_allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(ORDERS[10]),
        POOL_SIZE,
    );
    defer backing_allocator.free(backing_mem);

    const start_addr = @intFromPtr(backing_mem.ptr);
    const end_addr = start_addr + backing_mem.len;

    var buddy = try buddy_alloc.BuddyAllocator.init(start_addr, end_addr, backing_allocator);
    defer buddy.deinit();
    const buddy_iface = buddy.allocator();

    var handles = std.ArrayListUnmanaged(AllocHandle){};
    defer handles.deinit(backing_allocator);

    var alloc_map = buddy_alloc.BuddyAllocator.AllocationMap.init(backing_allocator);
    defer alloc_map.deinit();

    var prng = std.Random.DefaultPrng.init(SEED);
    var rand = prng.random();

    for (0..1_000_000) |i| {
        const action: Action = blk: {
            if (handles.items.len == 0) break :blk .alloc;
            if (handles.items.len == ACTIVE_CAP) break :blk .free;
            break :blk @enumFromInt(rand.intRangeAtMost(usize, 0, 1));
        };

        switch (action) {
            .alloc => {
                const alloc_type: AllocType = @enumFromInt(rand.intRangeAtMost(usize, 0, AllocType.NUM_TYPES - 1));
                const size = alloc_type.size();
                const ptr = AllocType.allocate(alloc_type, buddy_iface) catch {
                    std.debug.print(
                        "Action {} - Alloc: type {s}, len {}, FAILED - Out of Memory\n",
                        .{ i, alloc_type.toString(), size },
                    );
                    continue;
                };

                try handles.append(backing_allocator, .{
                    .alloc_type = alloc_type,
                    .addr = @intFromPtr(ptr),
                });

                try alloc_map.put(@intFromPtr(ptr), .{
                    .size = size,
                    .order = @intCast(alloc_type.idx()),
                });

                std.debug.print(
                    "Action {} - Alloc: type {s}, len {}, ptr: {x}\n",
                    .{ i, alloc_type.toString(), size, @intFromPtr(ptr) },
                );

                std.debug.assert(buddy.validateState(&alloc_map));
            },
            .free => {
                const idx = rand.intRangeAtMost(usize, 0, handles.items.len - 1);
                const h = handles.swapRemove(idx);
                _ = alloc_map.remove(h.addr);

                std.debug.print(
                    "Action {} - Free: type {s}, len {}, {x}\n",
                    .{ i, h.alloc_type.toString(), h.alloc_type.size(), h.addr },
                );

                AllocType.free(h.alloc_type, h.addr, buddy_iface);
                _ = alloc_map.remove(h.addr);

                std.debug.assert(buddy.validateState(&alloc_map));
            },
        }
    }
}
