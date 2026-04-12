const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PAddr = zag.memory.address.PAddr;
const SlabAllocator = zag.memory.allocators.slab.SlabAllocator;
const VAddr = zag.memory.address.VAddr;

pub const SharedMemoryAllocator = SlabAllocator(SharedMemory, false, 0, 64, true);

pub const SharedMemory = struct {
    pages: []PAddr,
    refcount: std.atomic.Value(u32),
    alloc_order: u4,

    pub const MAX_PAGES: u32 = 4096;

    pub fn size(self: *const SharedMemory) u64 {
        return @as(u64, self.pages.len) * paging.PAGE4K;
    }

    pub fn create(num_bytes: u64) !*SharedMemory {
        if (num_bytes == 0) return error.InvalidSize;
        const num_pages: u32 = @intCast(
            std.mem.alignForward(u64, num_bytes, paging.PAGE4K) / paging.PAGE4K,
        );
        if (num_pages > MAX_PAGES) return error.TooManyPages;

        const arch = @import("zag").arch.dispatch;
        const shm = allocator.create(SharedMemory) catch {
            arch.print("K: SHM slab alloc fail\n", .{});
            return error.OutOfMemory;
        };
        errdefer allocator.destroy(shm);

        const pages_slice = pages_allocator.alloc(PAddr, num_pages) catch {
            arch.print("K: SHM pages_slice alloc fail n={d}\n", .{num_pages});
            return error.OutOfMemory;
        };
        errdefer pages_allocator.free(pages_slice);

        // Try contiguous allocation via buddy (max order 10 = 1024 pages = 4MB).
        const max_buddy_pages: u32 = 1024;
        const rounded_pages = std.math.ceilPowerOfTwo(u32, num_pages) catch num_pages;
        const alloc_order: u4 = 0;

        if (rounded_pages <= max_buddy_pages) blk: {
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
                break :blk;
            };
            global.lock.unlockIrqRestore(irq);

            @memset(blk[0..alloc_size], 0);
            for (pages_slice, 0..) |*slot, i| {
                const page_virt = @intFromPtr(blk) + @as(u64, i) * paging.PAGE4K;
                slot.* = PAddr.fromVAddr(VAddr.fromInt(page_virt), null);
            }

            shm.* = .{
                .pages = pages_slice,
                .refcount = std.atomic.Value(u32).init(1),
                .alloc_order = order,
            };
            return shm;
        }

        // Fallback: per-page allocation (non-contiguous)
        shm.* = .{
            .pages = pages_slice[0..0],
            .refcount = std.atomic.Value(u32).init(1),
            .alloc_order = alloc_order,
        };
        errdefer shm.freePages();

        const pmm_iface = pmm.global_pmm.?.allocator();
        for (pages_slice) |*slot| {
            const page = pmm_iface.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
            const page_bytes: [*]u8 = @ptrCast(page);
            @memset(page_bytes[0..paging.PAGE4K], 0);
            slot.* = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
            shm.pages = pages_slice[0 .. shm.pages.len + 1];
        }

        return shm;
    }

    pub fn incRef(self: *SharedMemory) void {
        _ = self.refcount.fetchAdd(1, .monotonic);
    }

    pub fn decRef(self: *SharedMemory) void {
        const prev = self.refcount.fetchSub(1, .release);
        if (prev == 1) {
            _ = self.refcount.load(.acquire);
            self.destroy();
        }
    }

    fn destroy(self: *SharedMemory) void {
        self.freePages();
        pages_allocator.free(self.pages);
        allocator.destroy(self);
    }

    fn freePages(self: *SharedMemory) void {
        if (self.pages.len == 0) return;

        if (self.alloc_order > 0) {
            // Free the entire contiguous block at its original order
            const base_vaddr = VAddr.fromPAddr(self.pages[0], null);
            const block_size = @as(u64, @as(u32, 1) << self.alloc_order) * paging.PAGE4K;
            const buf: [*]u8 = @ptrFromInt(base_vaddr.addr);
            var global = &pmm.global_pmm.?;
            const irq = global.lock.lockIrqSave();
            global.backing_allocator.rawFree(
                buf[0..block_size],
                std.mem.Alignment.fromByteUnits(paging.PAGE4K),
                @returnAddress(),
            );
            global.lock.unlockIrqRestore(irq);
        } else {
            // Per-page free
            const pmm_iface = pmm.global_pmm.?.allocator();
            for (self.pages) |paddr| {
                const vaddr = VAddr.fromPAddr(paddr, null);
                const page: *paging.PageMem(.page4k) = @ptrFromInt(vaddr.addr);
                pmm_iface.destroy(page);
            }
        }
    }
};

pub var slab_allocator_instance: SharedMemoryAllocator = undefined;
pub var allocator: std.mem.Allocator = undefined;
pub var pages_allocator: std.mem.Allocator = undefined;
