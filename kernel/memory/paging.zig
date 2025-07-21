//! Page table definitions and utilities for x86_64 virtual memory management.
//!
//! This module provides low-level support for setting up and manipulating page tables
//! in long mode. It defines the `PageEntry` structure shared across all levels of the
//! 4-level paging hierarchy (PML4, PDPT, PD, PT), as well as enums representing access
//! flags, page sizes, and index extraction logic.
//!
//! The core of this module is `mapPage`, which constructs mappings by allocating
//! intermediate page tables on demand using a caller-supplied allocator. It is suitable
//! for both early-stage kernel memory setup (e.g., physical memory manager initialization)
//! and higher-level virtual memory management.
//!
//! Page size support includes 4 KiB, 2 MiB, and 1 GiB mappings, with optimizations for
//! early return when large or huge pages are requested.

const std = @import("std");

const allocator_interface = @import("allocator.zig");
const Allocator = allocator_interface.Allocator;

/// Represents supported page sizes for virtual memory mapping on x86_64.
///
/// Used to determine alignment and page table hierarchy level during page mapping.
pub const PageSize = enum(usize) {
    /// 4 KiB page (standard page size).
    Page4K = 4 * 1024,

    /// 2 MiB page (large page, skips one level of page tables).
    Page2M = 2 * 1024 * 1024,

    /// 1 GiB page (huge page, skips two levels of page tables).
    Page1G = 1 * 1024 * 1024 * 1024,
};

/// Page-level read/write permission flag for a page table entry.
pub const RW = enum(u1) {
    /// Read-only access.
    Readonly,

    /// Read/write access.
    ReadWrite,
};

/// Page-level privilege flag for a page table entry.
pub const User = enum(u1) {
    /// Page is accessible from userspace.
    User,

    /// Page is supervisor-only (kernel-mode access only).
    Supervisor,
};

/// Represents bit shifts for extracting indices at each level of the x86_64 page table hierarchy.
///
/// These values correspond to the bit boundaries for 4-level paging:
/// - 39: PML4 (top-level)
/// - 30: PDPT
/// - 21: PD
/// - 12: PT (lowest level, 4KiB pages)
const PageLevelShift = enum(u6) {
    PML4 = 39,
    PDPT = 30,
    PD = 21,
    PT = 12,
};

/// Represents a 64-bit page table entry in the x86_64 architecture.
///
/// This format is used for entries at all levels of the paging hierarchy (PML4, PDPT, PD, PT).
/// It includes flags for access control, memory attributes, and the physical address of
/// the next-level page table or mapped page.
const PageEntry = packed struct {
    /// Whether the page is present in physical memory (bit 0).
    present: bool,

    /// Read/write permission (bit 1).
    rw: RW,

    /// User/supervisor privilege level (bit 2).
    user: User,

    /// Enable write-through caching (bit 3).
    write_through: bool,

    /// Disable caching for this page (bit 4).
    cache_disable: bool,

    /// Indicates the page has been accessed (bit 5).
    accessed: bool,

    /// Indicates the page has been written to (bit 6, only meaningful in PTEs).
    dirty: bool,

    /// Indicates a large or huge page (bit 7).
    /// Used as the Page Size (PS) bit in PD/PT entries or as PAT in PTEs.
    huge_page: bool,

    /// Marks the page as global (bit 8, only meaningful in PTEs).
    global: bool,

    /// Ignored/reserved bits (bits 9–11).
    ignored: u3,

    /// Physical address of the next-level table or page (bits 12–51).
    addr: u40,

    /// Reserved or must-be-zero depending on context (bits 52–62).
    reserved: u11,

    /// No-execute bit (bit 63), if supported by the CPU.
    nx: bool,

    /// Returns the physical address encoded in this entry.
    pub fn getPaddr(self: *PageEntry) u40 {
        return @as(u40, self.addr) << @intFromEnum(PageLevelShift.PT);
    }

    /// Sets the physical address in this entry.
    ///
    /// The value is shifted to match the upper bits of the page table format (bits 12–51).
    pub fn setPaddr(self: *PageEntry, addr: u40) void {
        self.addr = @as(u40, addr >> @intFromEnum(PageLevelShift.PT));
    }
};

comptime {
    std.debug.assert(@sizeOf(PageEntry) == 8);
}

/// These are all aliases for `PageEntry`, used to clarify intent when indexing into
/// the various levels of the page table hierarchy. While the layout is identical,
/// using distinct names improves readability in code such as `mapPage`.
const PML4Entry = PageEntry;
const PDPTEntry = PageEntry;
const PDEntry = PageEntry;
const PTEntry = PageEntry;

/// Returns the PML4 index (bits 39–47) from a virtual address.
fn pml4_index(vaddr: usize) u9 {
    return @truncate(vaddr >> @intFromEnum(PageLevelShift.PML4));
}

/// Returns the PDPT index (bits 30–38) from a virtual address.
fn pdpt_index(vaddr: usize) u9 {
    return @truncate(vaddr >> @intFromEnum(PageLevelShift.PDPT));
}

/// Returns the Page Directory index (bits 21–29) from a virtual address.
fn pd_index(vaddr: usize) u9 {
    return @truncate(vaddr >> @intFromEnum(PageLevelShift.PD));
}

/// Returns the Page Table index (bits 12–20) from a virtual address.
fn pt_index(vaddr: usize) u9 {
    return @truncate(vaddr >> @intFromEnum(PageLevelShift.PT));
}

/// Reads the current value of the CR3 register, which contains the physical address
/// of the active PML4 (page table root) in x86_64.
///
/// This is useful for debugging or low-level memory management code to verify
/// which page table is currently in use.
pub fn read_cr3() usize {
    var value: usize = 0;
    asm volatile ("mov cr3, %[out]"
        : [out] "=r" (value),
    );
    return value;
}

/// Loads the CR3 register with the physical address of a new PML4 table.
///
/// This function switches the active page table by writing the physical address of
/// the provided `pml4` into the CR3 register. The CPU will then use the new page
/// hierarchy for all virtual-to-physical address translations.
///
/// The caller must ensure the provided PML4 is fully initialized and resides in
/// identity-mapped memory prior to calling this function. This function should be
/// called exactly once during early initialization, after all required mappings
/// have been installed.
///
/// - `pml4`: A pointer to the top-level page table (PML4), located in physical memory.
pub fn write_cr3(pml4: [*]PageEntry) void {
    const phys_addr: usize = @intFromPtr(pml4);
    asm volatile ("mov %[value], %%cr3"
        :
        : [value] "r" (phys_addr),
        : "memory"
    );
}

/// Maps a single physical page into the virtual address space using the provided PML4 table.
///
/// This function constructs the full 4-level page table hierarchy if necessary, allocating
/// intermediate tables on demand using the provided `Allocator`. It supports mapping 4 KiB,
/// 2 MiB, and 1 GiB pages, and will return early when a large or huge page is mapped directly
/// at a higher level (PD or PDPT respectively).
///
/// This is intended for both early memory setup (e.g., `RegionAllocator.initialize_page_tables`)
/// and later virtual memory management (e.g., in the VMM subsystem). Different allocator
/// strategies may be supplied depending on the context.
///
/// All page table entry types (`PML4Entry`, `PDPTEntry`, `PDEntry`, and `PTEntry`) are aliases
/// of the same `PageEntry` type. This improves clarity and readability while maintaining a
/// uniform layout for all levels.
///
/// Arguments:
/// - `pml4`: Pointer to the root page table (PML4), assumed to be identity-mapped.
/// - `paddr`: Physical address to map. Must be aligned to the specified `page_size`.
/// - `vaddr`: Virtual address where the mapping should be established. Must be aligned.
/// - `rw`: Read/write access permission (`Readonly` or `ReadWrite`).
/// - `user`: Privilege level (`User` or `Supervisor`).
/// - `page_size`: Granularity of the mapping (`Page4K`, `Page2M`, or `Page1G`).
/// - `allocator`: Allocator used for allocating intermediate page tables as needed.
///
/// Panics:
/// - If `paddr` or `vaddr` is not aligned to the specified `page_size`.
pub fn mapPage(
    pml4: [*]PML4Entry,
    paddr: usize,
    vaddr: usize,
    rw: RW,
    user: User,
    page_size: PageSize,
    allocator: *Allocator,
) void {
    std.debug.assert(std.mem.isAligned(
        paddr,
        @intFromEnum(page_size),
    ));
    std.debug.assert(std.mem.isAligned(
        vaddr,
        @intFromEnum(page_size),
    ));

    const flags = PageEntry{
        .present = true,
        .rw = rw,
        .user = user,
        .write_through = false,
        .cache_disable = false,
        .accessed = false,
        .dirty = false,
        .huge_page = false,
        .global = false,
        .ignored = 0,
        .addr = 0,
        .reserved = 0,
        .nx = false,
    };

    const pml4_idx = pml4_index(vaddr);
    const pdpt_idx = pdpt_index(vaddr);
    const pd_idx = pd_index(vaddr);
    const pt_idx = pt_index(vaddr);

    var pdpt_entry = &pml4[pml4_idx];
    if (!pdpt_entry.present) {
        const new_pdpt: [*]PDPTEntry = @alignCast(@ptrCast(allocator.alloc(
            @intFromEnum(PageSize.Page4K),
            @intFromEnum(PageSize.Page4K),
        )));
        pdpt_entry.* = flags;
        pdpt_entry.setPaddr(@intCast(@intFromPtr(
            new_pdpt,
        )));
    }
    const pdpt: [*]PDPTEntry = @ptrFromInt(pdpt_entry.getPaddr());

    // Map directly in PDPT for 1GiB pages
    if (page_size == .Page1G) {
        var entry = &pdpt[pdpt_idx];
        entry.* = flags;
        entry.huge_page = true;
        entry.setPaddr(@intCast(paddr));
        return;
    }

    var pd_entry = &pdpt[pdpt_idx];
    if (!pd_entry.present) {
        const new_pd: [*]PDEntry = @alignCast(@ptrCast(allocator.alloc(
            @intFromEnum(PageSize.Page4K),
            @intFromEnum(PageSize.Page4K),
        )));
        pd_entry.* = flags;
        pd_entry.setPaddr(@intCast(@intFromPtr(new_pd)));
    }
    const pd: [*]PDEntry = @ptrFromInt(pd_entry.getPaddr());

    // map directly in PD for 2MiB pages
    if (page_size == .Page2M) {
        var entry = &pd[pd_idx];
        entry.* = flags;
        entry.huge_page = true;
        entry.setPaddr(@intCast(paddr));
        return;
    }

    // else 4KiB pages are mapped in PT
    var pt_entry = &pd[pd_idx];
    if (!pt_entry.present) {
        const new_pt: [*]PTEntry = @alignCast(@ptrCast(allocator.alloc(
            @intFromEnum(PageSize.Page4K),
            @intFromEnum(PageSize.Page4K),
        )));
        pt_entry.* = flags;
        pt_entry.setPaddr(@intCast(@intFromPtr(new_pt)));
    }
    const pt: [*]PTEntry = @ptrFromInt(pt_entry.getPaddr());

    pt[pt_idx] = flags;
    pt[pt_idx].setPaddr(@intCast(paddr));
}
