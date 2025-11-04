//! Paging, address types, and helpers for x86-64.
//!
//! Defines strongly-typed physical/virtual address wrappers (`PAddr`, `VAddr`), the
//! unified `PageEntry` format used across all four paging levels, and mapping utilities
//! (`mapPage`, `physMapRegion`, `dropIdentityMap`) for early bring-up and runtime.
//! Assumes 4-level paging with optional 2 MiB / 1 GiB large pages, higher-half kernel,
//! and a physmap (direct map) at PML4 slot 511.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `Pml4SlotIndices` – PML4 slot reservations for kernel layouts.
//! - `MappingType` – base used for PAddr↔VAddr translation (physmap, identity).
//! - `PageSize` – supported page sizes (4 KiB, 2 MiB, 1 GiB).
//! - `RW` – readable/writable selector for entries.
//! - `User` – user/supervisor selector for entries.
//! - `Executeable` – executable/NX selector for entries.
//! - `Cacheable` – cacheability selector for entries.
//! - `PageLevelShift` – bit shifts for PML4/PDPT/PD/PT indices.
//! - `PAddr` – physical address wrapper with helpers.
//! - `PageEntry` – hardware page-table entry layout (all levels).
//! - `VAddr` – virtual address wrapper with helpers.
//! - `PDEntry` / `PDPTEntry` / `PML4Entry` / `PTEntry` – aliases to `PageEntry`.
//!
//! ## Constants
//! - `default_flags` – zeroed entry template for fresh tables.
//! - `PAGE_ALIGN` – required 4 KiB alignment for tables/pages.
//! - `PAGE_TABLE_SIZE` – number of entries per page table (512).
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `` - retrieve the physmapped vaddr of the current root page table
//! - `dropIdentityMap` – clear lower-half identity PML4 entries and reload CR3.
//! - `mapPage` – map one page (4 KiB/2 MiB/1 GiB), allocating tables on demand.
//! - `PageMem` – sized/ aligned struct type for allocator APIs (by page size).
//! - `physMapRegion` – cover a physical range using the largest suitable pages.
//! - `pml4_index` – compute PML4 index from a VAddr.
//! - `pml4SlotBase` – canonical base VAddr of a PML4 slot.
//! - `read_cr3` – read CR3 as a physical address plus flags.
//! - `write_cr3` – write CR3 (TLB shootdown).
//! - `pd_index` / `pdpt_index` / `pt_index` – lower-level index helpers.

const std = @import("std");

/// Top-level virtual address slots (PML4 indices) we reserve.
pub const Pml4SlotIndices = enum(u9) {
    uvmm_start = 0,
    uvmm_end = 255,
    kvmm_start = 256,
    kvmm_end = 510,
    physmap = 511,
};

/// Which base to use when translating between `PAddr` and `VAddr`.
pub const MappingType = enum {
    /// Physmap base (direct map of physical memory).
    physmap,
    /// Identity mapping for use by UEFI bootloader.
    identity,
};

/// Supported page sizes.
pub const PageSize = enum(u64) {
    /// 4 KiB page.
    Page4K = 4 * 1024,
    /// 2 MiB page.
    Page2M = 2 * 1024 * 1024,
    /// 1 GiB page.
    Page1G = 1 * 1024 * 1024 * 1024,
};

/// Read/write bit for entries.
pub const RW = enum(u1) {
    /// Read-only.
    ro,
    /// Read-write.
    rw,
};

/// User/supervisor bit for entries.
pub const User = enum(u1) {
    /// User-accessible.
    u,
    /// Supervisor-only.
    su,
};

/// Execute-disable (NX) flag for entries.
pub const Executeable = enum(u1) {
    /// Executable.
    x,
    /// Non-executable.
    nx,
};

/// Cacheability control for entries.
pub const Cacheable = enum(u1) {
    /// Cached (WB).
    cache,
    /// Uncached (CD=1).
    ncache,
};

/// Bit shifts for each page-table level.
const PageLevelShift = enum(u6) {
    /// PML4 shift (bits 47:39).
    PML4 = 39,
    /// PDPT shift (bits 38:30).
    PDPT = 30,
    /// PD shift (bits 29:21).
    PD   = 21,
    /// PT shift (bits 20:12).
    PT   = 12,
};

/// Physical address wrapper (bytes).
pub const PAddr = struct {
    /// Underlying physical address in bytes.
    addr: u64,

    /// Summary:
    /// Constructs a `PAddr` from a raw integer.
    ///
    /// Args:
    /// - `addr`: Raw physical address in bytes.
    ///
    /// Returns:
    /// - `PAddr` newly constructed.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn fromInt(addr: u64) PAddr {
        return .{ .addr = addr };
    }

    /// Summary:
    /// Translates a virtual address into a physical address using the given mapping base.
    ///
    /// Args:
    /// - `vaddr`: Virtual address to translate.
    /// - `type_`: Mapping base (`.physmap` or `.identity`) to use for translation.
    ///
    /// Returns:
    /// - `PAddr` computed physical address.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn fromVAddr(vaddr: VAddr, type_: MappingType) PAddr {
        const base_vaddr = switch (type_) {
            .physmap => pml4SlotBase(@intFromEnum(Pml4SlotIndices.physmap)),
            .identity => VAddr.fromInt(0),
        };
        const phys = vaddr.addr - base_vaddr.addr;
        return .{ .addr = phys };
    }

    /// Summary:
    /// Reinterprets this physical address as a pointer to `type_`.
    ///
    /// Args:
    /// - `self`: Receiver.
    /// - `type_`: Compile-time pointee type to cast to.
    ///
    /// Returns:
    /// - `type_` pointer value formed from `self.addr`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn getPtr(self: *const @This(), comptime type_: anytype) type_ {
        return @ptrFromInt(self.addr);
    }
};

/// Hardware page-table entry (works for all levels).
pub const PageEntry = packed struct {
    /// Present bit.
    present: bool,
    /// Read/write flag.
    rw: RW,
    /// User/supervisor flag.
    user: User,
    /// Write-through flag.
    write_through: bool,
    /// Cache disable.
    cache_disable: Cacheable,
    /// Accessed flag.
    accessed: bool,
    /// Dirty flag (leaf).
    dirty: bool,
    /// Large-page selector (PD/PT leaf).
    huge_page: bool,
    /// Global mapping flag.
    global: bool,
    /// Ignored bits.
    ignored: u3,
    /// Physical address bits (51:12).
    addr: u40,
    /// Reserved bits.
    reserved: u11,
    /// NX (execute-disable).
    nx: Executeable,

    /// Summary:
    /// Stores a physical address into the entry (requires 4 KiB alignment).
    ///
    /// Args:
    /// - `self`: Receiver.
    /// - `paddr`: Physical address to encode.
    ///
    /// Returns:
    /// - `void`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Panics if `paddr` is not 4 KiB-aligned.
    pub fn setPAddr(self: *PageEntry, paddr: PAddr) void {
        std.debug.assert(std.mem.isAligned(paddr.addr, PAGE_ALIGN.toByteUnits()));
        self.addr = @intCast(paddr.addr >> 12);
    }

    /// Summary:
    /// Extracts the physical address from the entry (lower 12 bits zeroed).
    ///
    /// Args:
    /// - `self`: Receiver.
    ///
    /// Returns:
    /// - `PAddr` decoded physical address.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn getPAddr(self: *const PageEntry) PAddr {
        const addr = @as(u64, self.addr) << 12;
        return PAddr.fromInt(addr);
    }
};

comptime {
    std.debug.assert(@sizeOf(PageEntry) == 8);
}

/// Virtual address wrapper (bytes).
pub const VAddr = struct {
    /// Underlying virtual address in bytes.
    addr: u64,

    /// Summary:
    /// Constructs a `VAddr` from a raw integer.
    ///
    /// Args:
    /// - `addr`: Raw virtual address in bytes.
    ///
    /// Returns:
    /// - `VAddr` newly constructed.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn fromInt(addr: u64) VAddr {
        return .{ .addr = addr };
    }

    /// Summary:
    /// Translates a physical address into a virtual address via the selected base.
    ///
    /// Args:
    /// - `paddr`: Physical address to translate.
    /// - `type_`: Mapping base (`.physmap` or `.identity`) to use.
    ///
    /// Returns:
    /// - `VAddr` computed virtual address.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn fromPAddr(paddr: PAddr, type_: MappingType) VAddr {
        const base_vaddr = switch (type_) {
            .physmap => pml4SlotBase(@intFromEnum(Pml4SlotIndices.physmap)),
            .identity => VAddr.fromInt(0),
        };
        const virt = paddr.addr + base_vaddr.addr;
        return .{ .addr = virt };
    }

    /// Summary:
    /// Reinterprets this virtual address as a pointer to `type_`.
    ///
    /// Args:
    /// - `self`: Receiver.
    /// - `type_`: Compile-time pointee type to cast to.
    ///
    /// Returns:
    /// - `type_` pointer value formed from `self.addr`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn getPtr(self: *const @This(), comptime type_: anytype) type_ {
        return @ptrFromInt(self.addr);
    }
};

/// Alias for page-directory entry type.
const PDEntry = PageEntry;
/// Alias for page-directory-pointer-table entry type.
const PDPTEntry = PageEntry;
/// Alias for top-level PML4 entry type.
const PML4Entry = PageEntry;
/// Alias for page-table entry type.
const PTEntry = PageEntry;

/// Zeroed entry template used for freshly allocated tables.
pub const default_flags = PageEntry{
    .present = false,
    .rw = .ro,
    .user = .su,
    .write_through = false,
    .cache_disable = .ncache,
    .accessed = false,
    .dirty = false,
    .huge_page = false,
    .global = false,
    .ignored = 0,
    .addr = 0,
    .reserved = 0,
    .nx = .nx,
};

pub const PAGE4K = @intFromEnum(PageSize.Page4K);
pub const PAGE2M = @intFromEnum(PageSize.Page2M);
pub const PAGE1G = @intFromEnum(PageSize.Page1G);

/// Required alignment for page tables and 4 KiB pages.
pub const PAGE_ALIGN = std.mem.Alignment.fromByteUnits(@intFromEnum(PageSize.Page4K));

/// Entries per page table.
pub const PAGE_TABLE_SIZE = 512;

/// Summary:
/// Copy the kernel PML4 mappings from the currently active address space into
/// `other`, covering slots `[kvmm_start .. 511]` (includes the physmap slot).
///
/// Args:
/// - `other`: Pointer to the destination PML4 table (virtual address).
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn copyKernelPml4Mappings(other: [*]PML4Entry) void {
    const src_pml4_vaddr = currentPml4VAddr();
    const src: [*]PML4Entry = src_pml4_vaddr.getPtr([*]PML4Entry);

    const start = @intFromEnum(Pml4SlotIndices.kvmm_start);
    for (start..PAGE_TABLE_SIZE) |i| {
        other[i] = src[i];
    }
}

/// Summary:
/// Returns the virtual address of the currently active PML4 by reading CR3,
/// masking off the low flag bits, and translating the physical base via the physmap.
///
/// Args:
/// - None.
///
/// Returns:
/// - `VAddr` canonical virtual address of the active PML4 page (4 KiB-aligned).
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn currentPml4VAddr() VAddr {
    const cr3 = read_cr3();
    const pml4_paddr = PAddr.fromInt(cr3.addr & ~@as(u64, 0xFFF));
    return VAddr.fromPAddr(pml4_paddr, .physmap);
}

/// Summary:
/// Drops the identity mapping for the lower half of the address space and reloads CR3.
/// Clears PML4 entries 0–255 to remove the early boot identity map once the kernel
/// runs in the higher half.
///
/// Args:
/// - None.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None (expects an active, canonical higher-half layout).
pub fn dropIdentityMap() void {
    const cr3 = read_cr3();

    const pml4_paddr = PAddr.fromInt(cr3.addr & ~@as(u64, 0xFFF));
    const pml4_vaddr = VAddr.fromPAddr(pml4_paddr, .physmap);
    const pml4 = pml4_vaddr.getPtr([*]PML4Entry);

    for (0..256) |i| {
        pml4[i] = default_flags;
    }

    write_cr3(pml4_paddr);
}

/// Summary:
/// Maps a single page (4 KiB / 2 MiB / 1 GiB) at `vaddr → paddr`, allocating
/// intermediate tables as needed, and honoring flags (rw/nx/user/cacheable).
///
/// Args:
/// - `pml4`: Pointer to active top-level PML4 (virtual).
/// - `paddr`: Physical address to map to.
/// - `vaddr`: Virtual address to map at.
/// - `rw`: Read/write setting for the leaf.
/// - `nx`: Executable/NX setting for the leaf.
/// - `cacheable`: Cacheability for the leaf.
/// - `user`: User/supervisor setting for the leaf.
/// - `page_size`: Page size to use (`Page4K`, `Page2M`, `Page1G`).
/// - `mapping_type`: How to translate newly allocated table addresses to PAddr.
/// - `allocator`: Allocator for on-demand table pages (4 KiB).
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None (OOM triggers a panic).
///
/// Panics:
/// - Panics on OOM while allocating tables.
/// - Panics if `paddr` or `vaddr` are not 4 KiB-aligned.
pub fn mapPage(
    pml4: [*]PML4Entry,
    paddr: PAddr,
    vaddr: VAddr,
    rw: RW,
    nx: Executeable,
    cacheable: Cacheable,
    user: User,
    page_size: PageSize,
    mapping_type: MappingType,
    allocator: std.mem.Allocator,
) void {
    std.debug.assert(std.mem.isAligned(paddr.addr, PAGE_ALIGN.toByteUnits()));
    std.debug.assert(std.mem.isAligned(vaddr.addr, PAGE_ALIGN.toByteUnits()));

    const parent_flags = PageEntry{
        .present = true,
        .rw = .rw,
        .user = user,
        .write_through = false,
        .cache_disable = .cache,
        .accessed = false,
        .dirty = false,
        .huge_page = false,
        .global = false,
        .ignored = 0,
        .addr = 0,
        .reserved = 0,
        .nx = .x,
    };

    const leaf_flags = PageEntry{
        .present = true,
        .rw = rw,
        .user = user,
        .write_through = false,
        .cache_disable = cacheable,
        .accessed = false,
        .dirty = false,
        .huge_page = false,
        .global = false,
        .ignored = 0,
        .addr = 0,
        .reserved = 0,
        .nx = nx,
    };

    const pml4_idx = pml4_index(vaddr);
    const pdpt_idx = pdpt_index(vaddr);
    const pd_idx = pd_index(vaddr);
    const pt_idx = pt_index(vaddr);

    std.debug.assert(pml4_idx < 512);
    std.debug.assert(pdpt_idx < 512);
    std.debug.assert(pd_idx < 512);
    std.debug.assert(pt_idx < 512);

    var pdpt_entry = &pml4[pml4_idx];
    if (!pdpt_entry.present) {
        const new_pdpt: []align(PAGE_ALIGN.toByteUnits()) PDPTEntry = allocator.alignedAlloc(
            PDPTEntry, PAGE_ALIGN, PAGE_TABLE_SIZE,
        ) catch @panic("Went OOM mapping pages!");
        @memset(new_pdpt, default_flags);
        pdpt_entry.* = parent_flags;
        const new_pdpt_vaddr = VAddr.fromInt(@intFromPtr(new_pdpt.ptr));
        const new_pdpt_paddr = PAddr.fromVAddr(new_pdpt_vaddr, mapping_type);
        pdpt_entry.setPAddr(new_pdpt_paddr);
    }
    const pdpt_entry_vaddr = VAddr.fromPAddr(pdpt_entry.getPAddr(), mapping_type);
    const pdpt = pdpt_entry_vaddr.getPtr([*]PDPTEntry);

    if (page_size == .Page1G) {
        var entry = &pdpt[pdpt_idx];
        entry.* = leaf_flags;
        entry.huge_page = true;
        entry.setPAddr(paddr);
        return;
    }

    var pd_entry = &pdpt[pdpt_idx];
    if (!pd_entry.present) {
        const new_pd: []align(PAGE_ALIGN.toByteUnits()) PDEntry = allocator.alignedAlloc(
            PDEntry, PAGE_ALIGN, PAGE_TABLE_SIZE,
        ) catch @panic("Went OOM mapping pages!");
        @memset(new_pd, default_flags);
        pd_entry.* = parent_flags;
        const new_pd_vaddr = VAddr.fromInt(@intFromPtr(new_pd.ptr));
        const new_pd_paddr = PAddr.fromVAddr(new_pd_vaddr, mapping_type);
        pd_entry.setPAddr(new_pd_paddr);
    }
    const pd_entry_vaddr = VAddr.fromPAddr(pd_entry.getPAddr(), mapping_type);
    const pd = pd_entry_vaddr.getPtr([*]PDEntry);

    if (page_size == .Page2M) {
        var entry = &pd[pd_idx];
        entry.* = leaf_flags;
        entry.huge_page = true;
        entry.setPAddr(paddr);
        return;
    }

    var pt_entry = &pd[pd_idx];
    if (!pt_entry.present) {
        const new_pt: []align(PAGE_ALIGN.toByteUnits()) PTEntry = allocator.alignedAlloc(
            PTEntry, PAGE_ALIGN, PAGE_TABLE_SIZE,
        ) catch @panic("Went OOM mapping pages!");
        @memset(new_pt, default_flags);
        pt_entry.* = parent_flags;
        const new_pt_vaddr = VAddr.fromInt(@intFromPtr(new_pt.ptr));
        const new_pt_paddr = PAddr.fromVAddr(new_pt_vaddr, mapping_type);
        pt_entry.setPAddr(new_pt_paddr);
    }
    const pt_entry_vaddr = VAddr.fromPAddr(pt_entry.getPAddr(), mapping_type);
    const pt = pt_entry_vaddr.getPtr([*]PTEntry);

    pt[pt_idx] = leaf_flags;
    pt[pt_idx].setPAddr(paddr);
}

/// Summary:
/// Returns a page-size-aligned region type for allocator APIs (typed scratch).
///
/// Args:
/// - `page_size`: Compile-time page size (`Page4K`, `Page2M`, `Page1G`).
///
/// Returns:
/// - `type`: Struct type `{ mem: [size]u8 align(size) }` suitable for table/page allocs.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn PageMem(comptime page_size: PageSize) type {
    const size_bytes = @intFromEnum(page_size);
    return struct { mem: [size_bytes]u8 align(size_bytes) };
}

/// Summary:
/// Identity-maps a physical range into the physmap using the fewest entries, choosing
/// 1 GiB / 2 MiB / 4 KiB pages based on alignment and remaining size.
///
/// Args:
/// - `pml4_vaddr`: Virtual address of the active PML4.
/// - `start_paddr`: Start of physical range (inclusive).
/// - `end_paddr`: End of physical range (exclusive).
/// - `allocator`: Allocator for on-demand tables.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None (invalid inputs assert; OOM panics).
///
/// Panics:
/// - Panics if inputs are misaligned or `end_paddr <= start_paddr`.
pub fn physMapRegion(
    pml4_vaddr: VAddr,
    start_paddr: PAddr,
    end_paddr: PAddr,
    allocator: std.mem.Allocator,
) void {
    const page4K = @intFromEnum(PageSize.Page4K);
    const page2M = @intFromEnum(PageSize.Page2M);
    const page1G = @intFromEnum(PageSize.Page1G);

    std.debug.assert(end_paddr.addr > start_paddr.addr);
    std.debug.assert(std.mem.isAligned(start_paddr.addr, page4K));
    std.debug.assert(std.mem.isAligned(end_paddr.addr, page4K));

    var paddr = start_paddr;
    while (paddr.addr < end_paddr.addr) {
        const vaddr = VAddr.fromPAddr(paddr, .physmap);
        const remaining = end_paddr.addr - paddr.addr;
        const chosen_size: u64 = blk: {
            if (std.mem.isAligned(paddr.addr, page1G) and remaining >= page1G) break :blk page1G;
            if (std.mem.isAligned(paddr.addr, page2M) and remaining >= page2M) break :blk page2M;
            break :blk page4K;
        };

        mapPage(
            @ptrFromInt(pml4_vaddr.addr),
            paddr,
            vaddr,
            .rw,
            .nx,
            .cache,
            .su,
            @enumFromInt(chosen_size),
            .identity,
            allocator,
        );

        paddr.addr += chosen_size;
    }
}

/// Summary:
/// Computes the PML4 index for a given virtual address.
///
/// Args:
/// - `vaddr`: Virtual address.
///
/// Returns:
/// - `u9` PML4 index (0..511).
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn pml4_index(vaddr: VAddr) u9 {
    return @truncate(vaddr.addr >> @intFromEnum(PageLevelShift.PML4));
}

/// Summary:
/// Computes the canonical base virtual address for a given PML4 slot.
///
/// Args:
/// - `slot`: PML4 index (0..511).
///
/// Returns:
/// - `VAddr` canonical base of the slot (sign-extended).
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn pml4SlotBase(slot: u9) VAddr {
    const raw: u64 = (@as(u64, slot) << 39);
    const base = if ((raw & 1 << 47) != 0) (raw | 0xFFFF000000000000) else raw;
    return VAddr.fromInt(base);
}

/// Summary:
/// Reads CR3 into a `PAddr` (including low flag bits).
///
/// Args:
/// - None.
///
/// Returns:
/// - `PAddr` raw CR3 value (address + flags).
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn read_cr3() PAddr {
    var value: u64 = 0;
    asm volatile ("mov %%cr3, %[out]"
        : [out] "=r" (value),
    );
    return PAddr.fromInt(value);
}

/// Summary:
/// Writes CR3 with the provided `pml4_paddr` (flushes TLB).
///
/// Args:
/// - `pml4_paddr`: PML4 physical address (flags permitted in low bits).
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn write_cr3(pml4_paddr: PAddr) void {
    asm volatile ("mov %[value], %%cr3"
        :
        : [value] "r" (pml4_paddr.addr),
        : .{ .memory = true });
}

/// Summary:
/// Computes PD index for a virtual address.
///
/// Args:
/// - `vaddr`: Virtual address.
///
/// Returns:
/// - `u9` PD index.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
fn pd_index(vaddr: VAddr) u9 {
    return @truncate(vaddr.addr >> @intFromEnum(PageLevelShift.PD));
}

/// Summary:
/// Computes PDPT index for a virtual address.
///
/// Args:
/// - `vaddr`: Virtual address.
///
/// Returns:
/// - `u9` PDPT index.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
fn pdpt_index(vaddr: VAddr) u9 {
    return @truncate(vaddr.addr >> @intFromEnum(PageLevelShift.PDPT));
}

/// Summary:
/// Computes PT index for a virtual address.
///
/// Args:
/// - `vaddr`: Virtual address.
///
/// Returns:
/// - `u9` PT index.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
fn pt_index(vaddr: VAddr) u9 {
    return @truncate(vaddr.addr >> @intFromEnum(PageLevelShift.PT));
}
