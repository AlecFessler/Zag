const std = @import("std");

pub const Word = u64; // set here so different sizes can be profiled
pub const WORD_BIT_SIZE = @bitSizeOf(Word);

pub fn BitmapFreeList(
    comptime using_getNextFree: bool,
) type {
    return struct {
        const Self = @This();
        base_addr: u64,
        block_size: u64,
        hint: if (using_getNextFree) u64 else void =
            if (using_getNextFree) 0,
        bitmap: []Word,
        allocator: std.mem.Allocator,

        pub fn init(
            base_addr: u64,
            block_size: u64,
            num_bits: u64,
            initially_free: bool,
            allocator: std.mem.Allocator,
        ) !Self {
            const bitmap_size = try std.math.divCeil(
                u64,
                num_bits,
                WORD_BIT_SIZE,
            );
            const bitmap = try allocator.alloc(u64, bitmap_size);
            if (initially_free) {
                @memset(bitmap, ~@as(Word, 0));
            } else {
                @memset(bitmap, @as(Word, 0));
            }

            const extra_bits = num_bits % WORD_BIT_SIZE;
            if (extra_bits > 0) {
                const mask: Word = (@as(Word, 1) << @intCast(extra_bits)) - 1;
                bitmap[bitmap.len - 1] &= mask;
            }

            return .{
                .base_addr = base_addr,
                .block_size = block_size,
                .bitmap = bitmap,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.bitmap);
        }

        pub fn getNextFree(self: *Self) ?u64 {
            if (!using_getNextFree) @compileError("Must build type with using_getNextFree flag if you plan to call this");
            if (self.hint == self.bitmap.len) return null;

            const next_free_word = self.bitmap[self.hint];
            std.debug.assert(next_free_word != 0);

            const first_free: u6 = @intCast(@ctz(next_free_word));

            const one: u64 = 1; // fixed width integer type for left hand side of shift
            self.bitmap[self.hint] &= ~(one << first_free);
            const bit_number = self.hint * WORD_BIT_SIZE + first_free;

            while (self.hint < self.bitmap.len) {
                if (self.bitmap[self.hint] != 0) break;
                self.hint += 1;
            }

            const addr = self.base_addr + bit_number * self.block_size;
            return addr;
        }

        pub fn setBit(self: *Self, addr: u64, val: u1) void {
            std.debug.assert(std.mem.isAligned(addr, self.block_size));

            const norm_addr = addr - self.base_addr;
            const bit_number = norm_addr / self.block_size;

            const word_idx = bit_number / WORD_BIT_SIZE;
            const bit_idx: u6 = @intCast(bit_number % WORD_BIT_SIZE);
            const one: Word = 1;

            if (val == 1) {
                self.bitmap[word_idx] |= (one << bit_idx);
                if (using_getNextFree and word_idx < self.hint) self.hint = word_idx;
            } else {
                self.bitmap[word_idx] &= ~(one << bit_idx);
                while (using_getNextFree and self.hint < self.bitmap.len) {
                    if (self.bitmap[self.hint] != 0) break;
                    self.hint += 1;
                }
            }
        }

        pub fn isFree(self: *Self, addr: u64) bool {
            std.debug.assert(std.mem.isAligned(addr, self.block_size));

            const norm_addr = addr - self.base_addr;
            const bit_number = norm_addr / self.block_size;

            const word_idx = bit_number / WORD_BIT_SIZE;
            const bit_idx: u6 = @intCast(bit_number % WORD_BIT_SIZE);

            const word = self.bitmap[word_idx];
            return ((word >> bit_idx) & 1) == 1;
        }
    };
}

test "setBit sets expected bit and updates hint backward" {
    const allocator = std.testing.allocator;
    var freelist = try BitmapFreeList(true).init(
        0x1000,
        0x1000,
        5,
        true,
        allocator,
    );
    defer freelist.deinit();

    _ = freelist.getNextFree();
    _ = freelist.getNextFree();
    _ = freelist.getNextFree();
    _ = freelist.getNextFree();
    _ = freelist.getNextFree();

    freelist.setBit(0x3000, 1);

    try std.testing.expect(freelist.bitmap[0] & (1 << 2) != 0);
    try std.testing.expectEqual(@as(?u64, 0x3000), freelist.getNextFree());
}

test "isFree correctly identifies free blocks" {
    const allocator = std.testing.allocator;
    var freelist = try BitmapFreeList(true).init(
        0x1000,
        0x1000,
        5,
        true,
        allocator,
    );
    defer freelist.deinit();

    try std.testing.expect(freelist.isFree(0x1000));
    try std.testing.expect(freelist.isFree(0x2000));
    try std.testing.expect(freelist.isFree(0x3000));
    try std.testing.expect(freelist.isFree(0x4000));
    try std.testing.expect(freelist.isFree(0x5000));

    _ = freelist.getNextFree();
    try std.testing.expect(!freelist.isFree(0x1000));
}

test "interleaved alloc/free correctly tracks hint" {
    const allocator = std.testing.allocator;
    var freelist = try BitmapFreeList(true).init(
        0x1000,
        0x1000,
        5,
        true,
        allocator,
    );
    defer freelist.deinit();

    try std.testing.expectEqual(@as(?u64, 0x1000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?u64, 0x2000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?u64, 0x3000), freelist.getNextFree());

    freelist.setBit(0x1000, 1);
    freelist.setBit(0x2000, 1);

    try std.testing.expectEqual(@as(?u64, 0x1000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?u64, 0x2000), freelist.getNextFree());

    freelist.setBit(0x2000, 1);
    try std.testing.expectEqual(@as(?u64, 0x2000), freelist.getNextFree());

    try std.testing.expectEqual(@as(?u64, 0x4000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?u64, 0x5000), freelist.getNextFree());
    try std.testing.expectEqual(@as(?u64, null), freelist.getNextFree());
}

test "extra bits in bitmap word are zeroed on init" {
    const allocator = std.testing.allocator;
    const num_bits = WORD_BIT_SIZE - 4;

    var freelist = try BitmapFreeList(true).init(
        0x0,
        0x1000,
        num_bits,
        true,
        allocator,
    );
    defer freelist.deinit();

    const last_word = freelist.bitmap[freelist.bitmap.len - 1];
    const mask: Word = (1 << (WORD_BIT_SIZE - 4)) - 1;

    try std.testing.expectEqual(last_word & ~mask, 0);
    try std.testing.expectEqual(last_word & mask, mask);
}

test "setBit clears a bit and advances hint when needed" {
    const allocator = std.testing.allocator;
    var freelist = try BitmapFreeList(true).init(
        0x1000,
        0x1000,
        3,
        false,
        allocator,
    );
    defer freelist.deinit();

    freelist.setBit(0x1000, 1);

    try std.testing.expect(freelist.hint == 0);
    try std.testing.expect(freelist.isFree(0x1000));

    const addr = freelist.getNextFree();
    try std.testing.expectEqual(addr, 0x1000);
    try std.testing.expect(!freelist.isFree(0x1000));

    try std.testing.expectEqual(freelist.hint, freelist.bitmap.len);
    try std.testing.expectEqual(freelist.getNextFree(), null);
}

test "bitmap without getNextFree support works for basic operations" {
    const allocator = std.testing.allocator;
    var freelist = try BitmapFreeList(false).init(
        0x1000,
        0x1000,
        5,
        true,
        allocator,
    );
    defer freelist.deinit();

    try std.testing.expect(freelist.isFree(0x1000));
    freelist.setBit(0x1000, 0);
    try std.testing.expect(!freelist.isFree(0x1000));
    freelist.setBit(0x1000, 1);
    try std.testing.expect(freelist.isFree(0x1000));
}
