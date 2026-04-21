//! AArch64 ASID (Address Space ID) allocator.
//!
//! ASIDs tag TLB entries so address-space switches do not require a full
//! TLB invalidate. The current kernel TTBR uses ASID 0, so id 0 is reserved
//! as the boot/kernel sentinel and is never handed out.
//!
//! Uses the 16-bit ASID space (TCR_EL1.AS = 1 -> 65536 ids). The allocator
//! is a bitmap of 1024 u64 words covering ids [0, 65536). Bit value 1 means
//! the id is allocated, 0 means free. An internal `hint` word index points at
//! the next-likely-free word to keep the common-case search O(1). 16-bit
//! ASIDs give effectively-infinite headroom for Zag's process counts, so
//! the allocator never needs to roll over or fall back to a TLB flush.
//!
//! References:
//! - ARM ARM D5.10 -- TLB tagging with ASID
//! - ARM ARM D13.2.131 -- TCR_EL1.AS (ASID size select)

const std = @import("std");
const zag = @import("zag");

const SpinLock = zag.utils.sync.SpinLock;

const asid_bits: u6 = 16;
const num_ids: u32 = 1 << asid_bits;
const words: usize = num_ids / 64;

var bitmap: [words]u64 = blk: {
    var init_bitmap: [words]u64 = .{0} ** words;
    init_bitmap[0] = 1;
    break :blk init_bitmap;
};
var hint: usize = 0;
var lock: SpinLock = .{};

pub fn allocate() ?u16 {
    const irq_state = lock.lockIrqSave();
    defer lock.unlockIrqRestore(irq_state);

    var scanned: usize = 0;
    var w = hint;
    while (scanned < words) {
        const word = bitmap[w];
        if (word != ~@as(u64, 0)) {
            const bit: u6 = @truncate(@ctz(~word));
            bitmap[w] = word | (@as(u64, 1) << bit);
            hint = w;
            return @intCast(w * 64 + @as(usize, bit));
        }
        w = (w + 1) % words;
        scanned += 1;
    }
    return null;
}

pub fn free(id: u16) void {
    std.debug.assert(id != 0);
    std.debug.assert(id < num_ids);

    const irq_state = lock.lockIrqSave();
    defer lock.unlockIrqRestore(irq_state);

    const w: usize = id / 64;
    const bit: u6 = @truncate(id % 64);
    const mask = @as(u64, 1) << bit;
    std.debug.assert((bitmap[w] & mask) != 0);
    bitmap[w] &= ~mask;
    if (w < hint) hint = w;
}
