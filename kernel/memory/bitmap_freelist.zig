const std = @import("std");

const fl = @import("freelist.zig");

const FreeList = fl.FreeList(usize);

const Word = u64; // set here so different sizes can be profiled
const word_bit_size = @bitSizeOf(Word);

const BitmapFreeList = struct {
    base_addr: usize,
    block_size: usize,
    hint: usize,
    bitmap: []Word,
    allocator: *std.mem.Allocator,

    pub fn init(
        base_addr: usize,
        block_size: usize,
        num_bits: usize,
        allocator: *std.mem.Allocator,
    ) !BitmapFreeList {
        const bitmap_size = try std.math.divCeil(
            usize,
            num_bits,
            word_bit_size,
        );
        const bitmap = try allocator.alloc(usize, bitmap_size);
        @memset(bitmap, ~@as(Word, 0));

        const extra_bits = num_bits % word_bit_size;
        if (extra_bits > 0) {
            const mask: Word = (@as(Word, 1) << @intCast(extra_bits)) - 1;
            bitmap[bitmap.len - 1] &= mask;
        }

        return .{
            .base_addr = base_addr,
            .block_size = block_size,
            .hint = 0,
            .bitmap = bitmap,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BitmapFreeList) void {
        self.allocator.free(self.bitmap);
    }

    pub fn freelist(self: *BitmapFreeList) FreeList {
        return .{
            .ptr = self,
            .vtable = &.{
                .getNextFree = getNextFree,
                .setFree = setFree,
                .isFree = isFree,
            },
        };
    }

    fn getNextFree(ptr: *anyopaque) ?[*]u8 {
        var self: *BitmapFreeList = @alignCast(@ptrCast(ptr));

        if (self.hint == self.bitmap.len) return null;

        const next_free_word = self.bitmap[self.hint];
        std.debug.assert(next_free_word != 0);

        const first_free: u6 = @intCast(@ctz(next_free_word));

        const one: u64 = 1; // fixed width integer type for left hand side of shift
        self.bitmap[self.hint] &= ~(one << first_free);
        const bit_number = self.hint * word_bit_size + first_free;

        while (self.hint < self.bitmap.len) {
            if (self.bitmap[self.hint] != 0) break;
            self.hint += 1;
        }

        const addr = self.base_addr + bit_number * self.block_size;
        return @ptrFromInt(addr);
    }

    pub fn setFree(ptr: *anyopaque, addr: [*]u8) void {
        var self: *BitmapFreeList = @alignCast(@ptrCast(ptr));
        const int_addr: usize = @intFromPtr(addr);

        std.debug.assert(std.mem.isAligned(int_addr, self.block_size));
        std.debug.assert(!isFree(ptr, addr));

        const norm_addr = int_addr - self.base_addr;
        const bit_number = norm_addr / self.block_size;

        const word_idx = bit_number / word_bit_size;
        const bit_idx: u6 = @intCast(bit_number % word_bit_size);

        const one: u64 = 1; // fixed width integer type for left hand side of shift
        self.bitmap[word_idx] |= (one << bit_idx);

        if (word_idx < self.hint) self.hint = word_idx;
    }

    pub fn isFree(ptr: *anyopaque, addr: [*]u8) bool {
        const self: *BitmapFreeList = @alignCast(@ptrCast(ptr));
        const int_addr: usize = @intFromPtr(addr);

        std.debug.assert(std.mem.isAligned(int_addr, self.block_size));

        const norm_addr = int_addr - self.base_addr;
        const bit_number = norm_addr / self.block_size;

        const word_idx = bit_number / word_bit_size;
        const bit_idx: u6 = @intCast(bit_number % word_bit_size);

        const word = self.bitmap[word_idx];
        return ((word >> bit_idx) & 1) == 1;
    }
};

test "getNextFree returns expected free blocks in order" {
    var allocator = std.testing.allocator;
    var freelist = try BitmapFreeList.init(0x1000, 0x1000, 5, &allocator);
    defer freelist.deinit();

    var free_list = freelist.freelist();

    try std.testing.expectEqual(@as(?usize, 0x1000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x2000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x3000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x4000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x5000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, null), free_list.getNextFree());
}

test "setFree sets expected bit and updates hint backward" {
    var allocator = std.testing.allocator;
    var freelist = try BitmapFreeList.init(0x1000, 0x1000, 5, &allocator);
    defer freelist.deinit();

    var free_list = freelist.freelist();

    _ = free_list.getNextFree();
    _ = free_list.getNextFree();
    _ = free_list.getNextFree();
    _ = free_list.getNextFree();
    _ = free_list.getNextFree();

    free_list.setFree(0x3000);

    try std.testing.expect(freelist.bitmap[0] & (1 << 2) != 0);
    try std.testing.expectEqual(@as(?usize, 0x3000), free_list.getNextFree());
}

test "isFree correctly identifies free blocks" {
    var allocator = std.testing.allocator;
    var freelist = try BitmapFreeList.init(0x1000, 0x1000, 5, &allocator);
    defer freelist.deinit();

    var free_list = freelist.freelist();

    try std.testing.expect(free_list.isFree(0x1000));
    try std.testing.expect(free_list.isFree(0x2000));
    try std.testing.expect(free_list.isFree(0x3000));
    try std.testing.expect(free_list.isFree(0x4000));
    try std.testing.expect(free_list.isFree(0x5000));

    _ = free_list.getNextFree(); // allocates 0x1000
    try std.testing.expect(!free_list.isFree(0x1000));
}

test "interleaved alloc/free correctly tracks hint" {
    var allocator = std.testing.allocator;
    var freelist = try BitmapFreeList.init(0x1000, 0x1000, 5, &allocator);
    defer freelist.deinit();

    var free_list = freelist.freelist();

    try std.testing.expectEqual(@as(?usize, 0x1000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x2000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x3000), free_list.getNextFree());

    free_list.setFree(0x1000);
    free_list.setFree(0x2000);

    try std.testing.expectEqual(@as(?usize, 0x1000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x2000), free_list.getNextFree());

    free_list.setFree(0x2000);
    try std.testing.expectEqual(@as(?usize, 0x2000), free_list.getNextFree());

    try std.testing.expectEqual(@as(?usize, 0x4000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x5000), free_list.getNextFree());
    try std.testing.expectEqual(@as(?usize, null), free_list.getNextFree());
}

test "extra bits in bitmap word are zeroed on init" {
    var allocator = std.testing.allocator;
    const num_bits = word_bit_size - 4;

    var freelist = try BitmapFreeList.init(0x0, 0x1000, num_bits, &allocator);
    defer freelist.deinit();

    const last_word = freelist.bitmap[freelist.bitmap.len - 1];
    const mask: Word = (1 << (word_bit_size - 4)) - 1;

    try std.testing.expectEqual(last_word & ~mask, 0);
    try std.testing.expectEqual(last_word & mask, mask);
}
