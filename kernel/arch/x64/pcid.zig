const std = @import("std");
const zag = @import("zag");

const SpinLock = zag.utils.sync.SpinLock;

/// Bitmap-based PCID (Process Context Identifier) allocator.
///
/// Intel SDM Vol 3A, Section 4.10.1 — Process-Context Identifiers (PCIDs).
/// PCIDs are 12-bit IDs (0..4095) placed in CR3[11:0] (when CR4.PCIDE=1) to
/// tag TLB entries so address-space switches do not flush the TLB.
///
/// Bit convention: 1 = allocated, 0 = free.
/// Id 0 is reserved as the boot/kernel sentinel (the value CR3 uses when
/// CR4.PCIDE=0) and is never handed out.

const pcid_bits: u16 = 12;
const pcid_count: u16 = 1 << pcid_bits;
const word_bits: u16 = 64;
const word_count: u16 = pcid_count / word_bits;

var bitmap: [word_count]u64 = init: {
    var b = [_]u64{0} ** word_count;
    b[0] = 1;
    break :init b;
};
var hint: u16 = 0;
var lock: SpinLock = .{};

pub fn allocate() ?u16 {
    const irq_state = lock.lockIrqSave();
    defer lock.unlockIrqRestore(irq_state);

    var scanned: u16 = 0;
    var w: u16 = hint;
    while (scanned < word_count) {
        const word = bitmap[w];
        if (word != ~@as(u64, 0)) {
            const free_bit: u6 = @intCast(@ctz(~word));
            bitmap[w] = word | (@as(u64, 1) << free_bit);
            hint = w;
            return w * word_bits + @as(u16, free_bit);
        }
        w = (w + 1) % word_count;
        scanned += 1;
    }
    return null;
}

pub fn free(id: u16) void {
    std.debug.assert(id != 0);
    std.debug.assert(id < pcid_count);

    const irq_state = lock.lockIrqSave();
    defer lock.unlockIrqRestore(irq_state);

    const w: u16 = id / word_bits;
    const b: u6 = @intCast(id % word_bits);
    const mask = @as(u64, 1) << b;
    std.debug.assert((bitmap[w] & mask) != 0);
    bitmap[w] &= ~mask;
    if (w < hint) hint = w;
}
