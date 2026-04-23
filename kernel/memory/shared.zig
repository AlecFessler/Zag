const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PAddr = zag.memory.address.PAddr;
const SlabAllocator = zag.memory.allocators.slab.SlabAllocator;
const VAddr = zag.memory.address.VAddr;

pub const SharedMemoryAllocator = SlabAllocator(SharedMemory, false, 0, 64, true);

/// A contiguous-backed shared memory region. Always a single buddy
/// allocation at `alloc_order`, covering `2^alloc_order` physical pages;
/// the user-visible extent is `num_pages` pages (≤ `2^alloc_order`), and
/// any trailing pages are internal buddy rounding that the caller does
/// not observe.
///
/// Contiguity is a hard invariant:
///   * `mem_shm_map` walks the range as `base + i*PAGE4K` rather than
///     chasing a page-index array.
///   * IOMMU programming can install one range instead of N per-page
///     PTEs in most cases.
///   * DMA exposure is safe by construction — the device sees one
///     contiguous IOVA.
///
/// The cost is a cap at the buddy's max order: `MAX_PAGES = 1024`
/// (4 MiB per SHM). Callers that want larger regions must attach
/// multiple SHMs side-by-side in their VMM.
pub const SharedMemory = struct {
    base_paddr: PAddr,
    num_pages: u32,
    alloc_order: u4,
    refcount: std.atomic.Value(u32),

    /// Max usable pages per SHM. Bounded by the buddy's max order
    /// (order 10 = 1024 pages = 4 MiB per region).
    pub const MAX_PAGES: u32 = 1024;

    pub fn size(self: *const SharedMemory) u64 {
        return @as(u64, self.num_pages) * paging.PAGE4K;
    }

    /// Physical address of the i-th page. Contiguity lets us compute
    /// it rather than look it up.
    pub fn pageAddr(self: *const SharedMemory, idx: usize) PAddr {
        return PAddr.fromInt(self.base_paddr.addr + @as(u64, idx) * paging.PAGE4K);
    }

    pub fn create(num_bytes: u64) !*SharedMemory {
        if (num_bytes == 0) return error.InvalidSize;
        // Bound num_bytes before narrowing to u32 — a raw @intCast of
        // `(num_bytes + PAGE4K - 1) / PAGE4K` panics for any num_bytes
        // ≥ 2^44 in safety-checked builds (ring-0 DoS from any caller
        // with mem_shm_create).
        if (num_bytes > @as(u64, MAX_PAGES) * paging.PAGE4K) return error.TooManyPages;
        const num_pages: u32 = @intCast(
            std.mem.alignForward(u64, num_bytes, paging.PAGE4K) / paging.PAGE4K,
        );
        if (num_pages == 0 or num_pages > MAX_PAGES) return error.TooManyPages;

        const rounded_pages = std.math.ceilPowerOfTwo(u32, num_pages) catch return error.TooManyPages;
        const order: u4 = @intCast(@ctz(rounded_pages));
        const alloc_size = @as(u64, rounded_pages) * paging.PAGE4K;

        const shm = allocator.create(SharedMemory) catch {
            arch.boot.print("K: SHM slab alloc fail\n", .{});
            return error.OutOfMemory;
        };
        errdefer allocator.destroy(shm);

        var global = &pmm.global_pmm.?;
        const blk = global.allocBlock(alloc_size) orelse {
            arch.boot.print("K: SHM buddy alloc fail pages={d}\n", .{rounded_pages});
            return error.OutOfMemory;
        };
        // Pages come back already zeroed from the PMM (§ zero-on-free).
        const base_paddr = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(blk)), null);

        shm.* = .{
            .base_paddr = base_paddr,
            .num_pages = num_pages,
            .alloc_order = order,
            .refcount = std.atomic.Value(u32).init(1),
        };
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
        allocator.destroy(self);
    }

    fn freePages(self: *SharedMemory) void {
        if (self.num_pages == 0) return;

        const block_pages = @as(u32, 1) << self.alloc_order;
        const block_size = @as(u64, block_pages) * paging.PAGE4K;
        const base_vaddr = VAddr.fromPAddr(self.base_paddr, null);
        const buf: [*]u8 = @ptrFromInt(base_vaddr.addr);

        var global = &pmm.global_pmm.?;
        global.freeBlock(buf[0..block_size]);
    }
};

pub var slab_allocator_instance: SharedMemoryAllocator = undefined;
pub var allocator: std.mem.Allocator = undefined;
