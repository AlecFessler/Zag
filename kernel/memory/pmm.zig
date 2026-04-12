const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;

const BuddyAllocator = zag.memory.allocators.buddy.BuddyAllocator;
const SpinLock = zag.utils.sync.SpinLock;

const MAX_CORES = 64;
const CACHE_REFILL_ORDER: u4 = 4;
const CACHE_REFILL_PAGES: u32 = @as(u32, 1) << CACHE_REFILL_ORDER;
const CACHE_MAX_PAGES: u32 = 64;

const PageNode = struct {
    next: ?*PageNode,
};

const PerCorePageCache = struct {
    head: ?*PageNode = null,
    count: u32 = 0,

    fn push(self: *PerCorePageCache, ptr: [*]u8) void {
        const node: *PageNode = @ptrCast(@alignCast(ptr));
        node.next = self.head;
        self.head = node;
        self.count += 1;
    }

    fn pop(self: *PerCorePageCache) ?[*]u8 {
        const node = self.head orelse return null;
        self.head = node.next;
        self.count -= 1;
        return @ptrCast(node);
    }
};

var page_caches: [MAX_CORES]PerCorePageCache = [_]PerCorePageCache{.{}} ** MAX_CORES;

pub const PhysicalMemoryManager = struct {
    backing_allocator: std.mem.Allocator,
    lock: SpinLock = .{},

    pub fn init(backing_allocator: std.mem.Allocator) PhysicalMemoryManager {
        return .{
            .backing_allocator = backing_allocator,
        };
    }

    pub fn allocator(self: *PhysicalMemoryManager) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ptr: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *PhysicalMemoryManager = @ptrCast(@alignCast(ptr));

        if (len == paging.PAGE4K and sched.initialized) {
            const irq = arch.saveAndDisableInterrupts();
            const cache = &page_caches[arch.coreID()];

            if (cache.pop()) |page| {
                arch.restoreInterrupts(irq);
                return page;
            }

            self.lock.lock();

            const bulk = self.backing_allocator.rawAlloc(
                paging.PAGE4K * CACHE_REFILL_PAGES,
                std.mem.Alignment.fromByteUnits(paging.PAGE4K),
                ret_addr,
            ) orelse {
                const single = self.backing_allocator.rawAlloc(len, alignment, ret_addr);
                self.lock.unlock();
                arch.restoreInterrupts(irq);
                return single;
            };

            const buddy: *BuddyAllocator = @ptrCast(@alignCast(self.backing_allocator.ptr));
            var batch = buddy.splitAllocation(@intFromPtr(bulk), 0);
            self.lock.unlock();

            while (batch.pop()) |page| {
                cache.push(@ptrCast(page));
            }

            const result = cache.pop().?;
            arch.restoreInterrupts(irq);
            return result;
        }

        const irq = self.lock.lockIrqSave();
        defer self.lock.unlockIrqRestore(irq);
        return self.backing_allocator.rawAlloc(len, alignment, ret_addr);
    }

    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *PhysicalMemoryManager = @ptrCast(@alignCast(ptr));

        // only touch per core cache if the scheduler has been fully initialized (ie, system is fully booted)
        // otherwise arch.coreID() will access an array that is undefined
        if (buf.len == paging.PAGE4K and sched.initialized) {
            const irq = arch.saveAndDisableInterrupts();
            const cache = &page_caches[arch.coreID()];

            if (cache.count < CACHE_MAX_PAGES) {
                cache.push(buf.ptr);
                arch.restoreInterrupts(irq);
                return;
            }

            self.lock.lock();
            var i: u32 = 0;
            while (i < CACHE_MAX_PAGES / 2) {
                const page = cache.pop().?;
                self.backing_allocator.rawFree(
                    page[0..paging.PAGE4K],
                    std.mem.Alignment.fromByteUnits(paging.PAGE4K),
                    ret_addr,
                );
                i += 1;
            }
            self.lock.unlock();

            cache.push(buf.ptr);
            arch.restoreInterrupts(irq);
            return;
        }

        const irq = self.lock.lockIrqSave();
        defer self.lock.unlockIrqRestore(irq);
        self.backing_allocator.rawFree(buf, alignment, ret_addr);
    }

    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }
};

pub var global_pmm: ?PhysicalMemoryManager = null;

/// Number of physical pages currently free for allocation. Used by the
/// `sys_info` syscall to populate `SysInfo.mem_free` (§2.15.3, §21).
///
/// Queries the buddy allocator's internal `free_pages` counter (pages sitting
/// on any order-N freelist) and adds every page currently held in the
/// per-core `PerCorePageCache` rings. Per-core cache entries were allocated
/// from the buddy at refill time, so the buddy's own counter no longer sees
/// them as free — but to userspace they are observably free, and the next
/// `alloc` on this core pops them without touching the buddy.
///
/// O(MAX_CORES) in the worst case (only the per-core cache count fields
/// are touched, not their intrusive freelists); acquires `pmm.lock` to
/// serialize with the buddy counter's updates under `alloc`/`free`.
pub fn freePageCount() u64 {
    if (global_pmm == null) return 0;
    const pmm_ptr: *PhysicalMemoryManager = &global_pmm.?;
    const irq = pmm_ptr.lock.lockIrqSave();
    defer pmm_ptr.lock.unlockIrqRestore(irq);

    const buddy: *BuddyAllocator = @ptrCast(@alignCast(pmm_ptr.backing_allocator.ptr));
    var total = buddy.free_pages;

    // Per-core cache pages were allocated from the buddy (via
    // `splitAllocation`) and are observably free to userspace. Each
    // cache node is a 4 KiB page; `count` is the number of nodes.
    var i: usize = 0;
    while (i < MAX_CORES) {
        total += page_caches[i].count;
        i += 1;
    }
    return total;
}

/// Static total physical page count established by the buddy allocator
/// at `addRegion` time. Used by `sys_info` to populate `SysInfo.mem_total`
/// (§2.15.2, §21). Does not change at runtime.
pub fn totalPageCount() u64 {
    if (global_pmm == null) return 0;
    const pmm_ptr: *PhysicalMemoryManager = &global_pmm.?;
    const irq = pmm_ptr.lock.lockIrqSave();
    defer pmm_ptr.lock.unlockIrqRestore(irq);

    const buddy: *BuddyAllocator = @ptrCast(@alignCast(pmm_ptr.backing_allocator.ptr));
    return buddy.total_pages;
}
