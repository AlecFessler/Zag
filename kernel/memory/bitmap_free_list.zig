const std = @import("std");
const Word = u64; // set here so different sizes can be profiled
const word_bit_size = @bitSizeOf(Word);

const BitmapFreeList = struct {
    base_addr: usize,
    block_size: usize,
    hint: usize,
    bitmap: []Word,

    pub fn init(
        base_addr: usize,
        block_size: usize,
        bitmap: []Word,
    ) BitmapFreeList {
        return .{
            .base_addr = base_addr,
            .block_size = block_size,
            .hint = 0,
            .bitmap = bitmap,
        };
    }

    pub fn getNextFree(self: *BitmapFreeList) ?usize {
        if (self.hint == self.bitmap.len) return null;

        const next_free_word = self.bitmap[self.hint];
        const first_free: u6 = @intCast(@ctz(next_free_word));

        std.debug.assert(first_free != word_bit_size); // hint lied!

        const one: u64 = 1; // fixed width integer type for left hand side of shift
        self.bitmap[self.hint] &= ~(one << first_free);
        const bit_number = self.hint * word_bit_size + first_free;

        while (self.hint < self.bitmap.len) {
            if (@ctz(self.bitmap[self.hint]) != word_bit_size) break;
            self.hint += 1;
        }

        return self.base_addr + bit_number * self.block_size;
    }

    pub fn setFree(self: *BitmapFreeList, addr: usize) void {
        std.debug.assert(std.mem.isAligned(addr, self.block_size));

        const norm_addr = addr - self.base_addr;
        const bit_number = norm_addr / self.block_size;

        const word_idx = bit_number / word_bit_size;
        const bit_idx: u6 = @intCast(bit_number % word_bit_size);

        const one: u64 = 1; // fixed width integer type for left hand side of shift
        self.bitmap[word_idx] |= (one << bit_idx);

        if (word_idx < self.hint) self.hint = word_idx;
    }

    pub fn isFree(self: *BitmapFreeList, addr: usize) bool {
        std.debug.assert(std.mem.isAligned(addr, self.block_size));

        const norm_addr = addr - self.base_addr;
        const bit_number = norm_addr / self.block_size;

        const word_idx = bit_number / word_bit_size;
        const bit_idx: u6 = @intCast(bit_number % word_bit_size);

        const word = self.bitmap[word_idx];
        return ((word >> bit_idx) & 1) == 1;
    }
};

test "getNextFree returns expected free blocks in order" {
    var bitmap: [1]u64 = [_]u64{0b11110};
    var freelist = BitmapFreeList.init(0x1000, 0x1000, &bitmap);

    try std.testing.expectEqual(@as(?usize, 0x2000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x3000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x4000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x5000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, null), freelist.getNextFree());
}

test "setFree sets expected bit and updates hint backward" {
    var bitmap: [1]u64 = [_]u64{0b11110};
    var freelist = BitmapFreeList.init(0x1000, 0x1000, &bitmap);

    try std.testing.expectEqual(@as(?usize, 0x2000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x3000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x4000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x5000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, null), freelist.getNextFree());

    freelist.setFree(0x3000);
    try std.testing.expectEqual(@as(u64, 1 << 2), bitmap[0]);
    try std.testing.expectEqual(@as(?usize, 0x3000), freelist.getNextFree());
}

test "isFree correctly identifies free blocks" {
    var bitmap: [1]u64 = [_]u64{0b10101};
    var freelist = BitmapFreeList.init(0x0, 0x1000, &bitmap);

    try std.testing.expect(freelist.isFree(0x0));
    try std.testing.expect(!freelist.isFree(0x1000));
    try std.testing.expect(freelist.isFree(0x2000));
    try std.testing.expect(!freelist.isFree(0x3000));
    try std.testing.expect(freelist.isFree(0x4000));
}

test "interleaved alloc/free correctly tracks hint" {
    var bitmap: [1]u64 = [_]u64{0b11111};
    var freelist = BitmapFreeList.init(0x1000, 0x1000, &bitmap);

    try std.testing.expectEqual(@as(?usize, 0x1000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x2000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x3000), freelist.getNextFree());

    freelist.setFree(0x1000);
    freelist.setFree(0x2000);

    try std.testing.expectEqual(@as(?usize, 0x1000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x2000), freelist.getNextFree());

    freelist.setFree(0x2000);
    try std.testing.expectEqual(@as(?usize, 0x2000), freelist.getNextFree());

    try std.testing.expectEqual(@as(?usize, 0x4000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, 0x5000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?usize, null), freelist.getNextFree());
}
