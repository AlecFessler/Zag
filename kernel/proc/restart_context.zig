const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

/// Per-process restart state. Inlined as `?RestartContext` in `Process`;
/// no separate allocator. The ghost data segment is backed by a single
/// contiguous buddy allocation — `ghostSlice()` returns a physmap view
/// over those pages.
///
/// When `data_size == 0` the context carries only the entry point and
/// no ghost pages are allocated (`deinit()` is a no-op in that case).
pub const RestartContext = struct {
    entry_point: VAddr,
    data_vaddr: VAddr,
    data_size: u64,
    ghost_base: PAddr,
    ghost_order: u4,

    pub fn init(entry: VAddr, data_vaddr: VAddr, data_content: []const u8) !RestartContext {
        if (data_content.len == 0) {
            return .{
                .entry_point = entry,
                .data_vaddr = data_vaddr,
                .data_size = 0,
                .ghost_base = PAddr.fromInt(0),
                .ghost_order = 0,
            };
        }

        // Round up to page count, then to a buddy-servable power of two.
        // The ghost allocation is contiguous so we can access it through
        // the kernel physmap with a plain `@ptrFromInt` later, and free
        // it in one `rawFree` at the same order.
        const num_pages_u64 = std.mem.alignForward(u64, data_content.len, paging.PAGE4K) / paging.PAGE4K;
        if (num_pages_u64 == 0 or num_pages_u64 > std.math.maxInt(u32)) return error.TooManyPages;
        const num_pages: u32 = @intCast(num_pages_u64);
        const rounded_pages = std.math.ceilPowerOfTwo(u32, num_pages) catch return error.TooManyPages;
        const order: u4 = @intCast(@ctz(rounded_pages));
        const alloc_size = @as(u64, rounded_pages) * paging.PAGE4K;

        var global = &pmm.global_pmm.?;
        const irq = global.lock.lockIrqSave();
        const blk = global.backing_allocator.rawAlloc(
            alloc_size,
            std.mem.Alignment.fromByteUnits(paging.PAGE4K),
            @returnAddress(),
        ) orelse {
            global.lock.unlockIrqRestore(irq);
            return error.OutOfMemory;
        };
        global.lock.unlockIrqRestore(irq);

        @memcpy(blk[0..data_content.len], data_content);
        if (alloc_size > data_content.len) {
            @memset(blk[data_content.len..alloc_size], 0);
        }

        return .{
            .entry_point = entry,
            .data_vaddr = data_vaddr,
            .data_size = data_content.len,
            .ghost_base = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(blk)), null),
            .ghost_order = order,
        };
    }

    pub fn deinit(self: *RestartContext) void {
        if (self.data_size == 0) return;
        const block_pages = @as(u32, 1) << self.ghost_order;
        const block_size = @as(u64, block_pages) * paging.PAGE4K;
        const base_vaddr = VAddr.fromPAddr(self.ghost_base, null);
        const buf: [*]u8 = @ptrFromInt(base_vaddr.addr);
        var global = &pmm.global_pmm.?;
        const irq = global.lock.lockIrqSave();
        global.backing_allocator.rawFree(
            buf[0..block_size],
            std.mem.Alignment.fromByteUnits(paging.PAGE4K),
            @returnAddress(),
        );
        global.lock.unlockIrqRestore(irq);
        self.data_size = 0;
    }

    /// Physmap view of the saved ghost bytes. Valid until `deinit()`.
    pub fn ghostSlice(self: *const RestartContext) []const u8 {
        if (self.data_size == 0) return &.{};
        const base = VAddr.fromPAddr(self.ghost_base, null).addr;
        return @as([*]const u8, @ptrFromInt(base))[0..self.data_size];
    }
};
