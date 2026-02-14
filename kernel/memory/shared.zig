const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PAddr = zag.memory.address.PAddr;
const SharedMemoryRights = zag.perms.permissions.SharedMemoryRights;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const VAddr = zag.memory.address.VAddr;

pub const SharedMemoryAllocator = SlabAllocator(SharedMemory, false, 0, 64);

pub const SharedMemory = struct {
    pages: [MAX_PAGES]PAddr,
    num_pages: u32,
    max_rights: SharedMemoryRights,
    refcount: std.atomic.Value(u32),

    pub const MAX_PAGES = 256;

    pub fn create(num_bytes: u64, max_rights: SharedMemoryRights) !*SharedMemory {
        if (num_bytes == 0) return error.InvalidSize;

        const num_pages: u32 = @intCast(
            std.mem.alignForward(u64, num_bytes, paging.PAGE4K) / paging.PAGE4K,
        );
        if (num_pages > MAX_PAGES) return error.TooManyPages;

        const shm = try allocator.create(SharedMemory);
        errdefer allocator.destroy(shm);

        shm.* = .{
            .pages = undefined,
            .num_pages = 0,
            .max_rights = max_rights,
            .refcount = std.atomic.Value(u32).init(1),
        };

        const pmm_iface = pmm.global_pmm.?.allocator();
        errdefer shm.freePages();

        var i: u32 = 0;
        while (i < num_pages) : (i += 1) {
            const page = pmm_iface.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
            const page_bytes: [*]u8 = @ptrCast(page);
            @memset(page_bytes[0..paging.PAGE4K], 0);
            shm.pages[i] = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
            shm.num_pages += 1;
        }

        return shm;
    }

    pub fn incRef(self: *SharedMemory) void {
        _ = self.refcount.fetchAdd(1, .monotonic);
    }

    pub fn decRef(self: *SharedMemory) void {
        const prev = self.refcount.fetchSub(1, .release);
        if (prev == 1) {
            std.atomic.fence(.acquire);
            self.destroy();
        }
    }

    fn destroy(self: *SharedMemory) void {
        self.freePages();
        allocator.destroy(self);
    }

    fn freePages(self: *SharedMemory) void {
        const pmm_iface = pmm.global_pmm.?.allocator();
        for (self.pages[0..self.num_pages]) |paddr| {
            const vaddr = VAddr.fromPAddr(paddr, null);
            const page: *paging.PageMem(.page4k) = @ptrFromInt(vaddr.addr);
            pmm_iface.destroy(page);
        }
    }
};

pub var slab_allocator_instance: SharedMemoryAllocator = undefined;
pub var allocator: std.mem.Allocator = undefined;
