//! Bitmap-backed free list for fixed-size blocks.
//!
//! Provides a compact allocator-style bitmap where each bit represents a block:
//! `1` means free, `0` means allocated. Supports constant-time bit set/clear and
//! an optional O(1) “next free” scan using a moving word hint.

const std = @import("std");

/// Underlying bitmap word type.
pub const Word = u64;

/// Number of bits per `Word`.
pub const WORD_BIT_SIZE = @bitSizeOf(Word);

/// Factory for a bitmap free list type.
///
/// Compile-time parameter:
/// - `using_getNextFree`: when true, enables the `getNextFree()` fast path with
///   a moving word index (`hint`). When false, that API is unavailable.
///
/// Bit convention:
/// - `1` = free
/// - `0` = allocated
pub fn BitmapFreeList(
    comptime using_getNextFree: bool,
) type {
    return struct {
        const Self = @This();

        /// Base address of the first block represented by bit 0.
        base_addr: u64,
        /// Size in bytes of each fixed block.
        block_size: u64,
        /// Word index hint for the next free search (only when enabled).
        hint: if (using_getNextFree) u64 else void =
            if (using_getNextFree) 0,
        /// The bitmap storage (1 = free, 0 = allocated).
        bitmap: []Word,
        /// Allocator used to allocate/free the bitmap buffer.
        allocator: std.mem.Allocator,

        /// Creates a bitmap with `num_bits` blocks starting at `base_addr`
        /// in `block_size` increments. If `initially_free` is true, all bits are set to 1
        /// (free); otherwise all are 0 (allocated). The tail word is masked to `num_bits`.
        ///
        /// Arguments:
        /// - `base_addr`: address represented by bit 0 (block 0).
        /// - `block_size`: size in bytes of each block (must divide represented addresses).
        /// - `num_bits`: number of blocks represented by the bitmap.
        /// - `initially_free`: when true, mark all blocks free.
        /// - `allocator`: backing allocator for the bitmap buffer.
        ///
        /// Returns:
        /// - Initialized `Self` on success, or an allocation error.
        pub fn init(
            base_addr: u64,
            block_size: u64,
            num_bits: u64,
            initially_free: bool,
            allocator: std.mem.Allocator,
        ) !Self {
            const bitmap_size = try std.math.divCeil(u64, num_bits, WORD_BIT_SIZE);
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

        /// Releases the bitmap storage.
        ///
        /// Arguments:
        /// - `self`: bitmap instance whose internal buffer will be freed.
        ///
        /// Returns:
        /// - Nothing.
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.bitmap);
        }

        /// Returns the address of the next free block and marks it allocated (bit → 0).
        ///
        /// Only available when the type was instantiated with `using_getNextFree = true`.
        /// Complexity: amortized O(1) across allocations as the `hint` advances by words.
        ///
        /// Arguments:
        /// - `self`: bitmap instance.
        ///
        /// Returns:
        /// - Address of the next free block, or `null` if no free bit remains at/after the hint.
        pub fn getNextFree(self: *Self) ?u64 {
            if (!using_getNextFree) @compileError("Must build type with using_getNextFree flag if you plan to call this");
            if (self.hint == self.bitmap.len) return null;

            const next_free_word = self.bitmap[self.hint];
            std.debug.assert(next_free_word != 0);

            const first_free: u6 = @intCast(@ctz(next_free_word));

            const one: u64 = 1;
            self.bitmap[self.hint] &= ~(one << first_free);
            const bit_number = self.hint * WORD_BIT_SIZE + first_free;

            while (self.hint < self.bitmap.len) {
                if (self.bitmap[self.hint] != 0) break;
                self.hint += 1;
            }

            const addr = self.base_addr + bit_number * self.block_size;
            return addr;
        }

        /// Sets the bit corresponding to `addr` to `val` (1 = free, 0 = allocated).
        ///
        /// `addr` must be aligned to `block_size` and within the represented range.
        /// Adjusts the `hint` to maintain a fast path when enabling free bits.
        ///
        /// Arguments:
        /// - `self`: bitmap instance.
        /// - `addr`: block base address whose bit should change.
        /// - `val`: 1 to mark free, 0 to mark allocated.
        ///
        /// Returns:
        /// - Nothing.
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

        /// Returns true if the block at `addr` is free (bit = 1).
        ///
        /// Arguments:
        /// - `self`: bitmap instance.
        /// - `addr`: block base address to query (must be `block_size`-aligned).
        ///
        /// Returns:
        /// - `true` when the corresponding bit is 1 (free), otherwise `false`.
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
