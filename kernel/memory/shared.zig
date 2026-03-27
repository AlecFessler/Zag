const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PAddr = zag.memory.address.PAddr;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const VAddr = zag.memory.address.VAddr;

pub const SharedMemoryAllocator = SlabAllocator(SharedMemory, false, 0, 64, true);

pub const SharedMemory = struct {
    pages: []PAddr,
    refcount: std.atomic.Value(u32),

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

        shm.* = .{
            .pages = pages_slice[0..0],
            .refcount = std.atomic.Value(u32).init(1),
        };

        const pmm_iface = pmm.global_pmm.?.allocator();
        errdefer shm.freePages();
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
        const pmm_iface = pmm.global_pmm.?.allocator();
        for (self.pages) |paddr| {
            const vaddr = VAddr.fromPAddr(paddr, null);
            const page: *paging.PageMem(.page4k) = @ptrFromInt(vaddr.addr);
            pmm_iface.destroy(page);
        }
    }
};

pub var slab_allocator_instance: SharedMemoryAllocator = undefined;
pub var allocator: std.mem.Allocator = undefined;
pub var pages_allocator: std.mem.Allocator = undefined;
