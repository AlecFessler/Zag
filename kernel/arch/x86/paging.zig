const std = @import("std");

const vga = @import("vga.zig");

extern const _kernel_base_vaddr: u8;

pub const PAGE_TABLE_SIZE = 512;

pub const PageSize = enum(u64) {
    Page4K = 4 * 1024,
    Page2M = 2 * 1024 * 1024,
    Page1G = 1 * 1024 * 1024 * 1024,
};

const PAGE_ALIGN = std.mem.Alignment.fromByteUnits(@intFromEnum(PageSize.Page4K));

pub fn PageMem(comptime page_size: PageSize) type {
    const size_bytes = @intFromEnum(page_size);
    return struct {
        mem: [size_bytes]u8 align(size_bytes),
    };
}

pub const RW = enum(u1) {
    Readonly,
    ReadWrite,
};

pub const User = enum(u1) {
    User,
    Supervisor,
};

const PageLevelShift = enum(u6) {
    PML4 = 39,
    PDPT = 30,
    PD = 21,
    PT = 12,
};

const PageEntry = packed struct {
    present: bool,
    rw: RW,
    user: User,
    write_through: bool,
    cache_disable: bool,
    accessed: bool,
    dirty: bool,
    huge_page: bool,
    global: bool,
    ignored: u3,
    addr: u40,
    reserved: u11,
    nx: bool,

    pub fn setPaddr(self: *PageEntry, paddr: u64) void {
        std.debug.assert(std.mem.isAligned(paddr, PAGE_ALIGN.toByteUnits()));
        self.addr = @intCast(paddr >> 12);
    }

    pub fn getPaddr(self: *const PageEntry) u64 {
        return @as(u64, self.addr) << 12;
    }
};

comptime {
    std.debug.assert(@sizeOf(PageEntry) == 8);
}

const PML4Entry = PageEntry;
const PDPTEntry = PageEntry;
const PDEntry = PageEntry;
const PTEntry = PageEntry;

pub const AddressSpace = enum(u9) {
    pmm = 511,
    kvmm = 510,
    uvmm = 509,
};

pub fn pml4SlotBase(slot: u9) u64 {
    const raw: u64 = (@as(u64, slot) << 39);
    return if ((raw & 1 << 47) != 0) (raw | 0xFFFF000000000000) else raw;
}

pub fn physToVirt(paddr: u64) u64 {
    const kernel_base_vaddr: u64 = @intCast(@intFromPtr(&_kernel_base_vaddr));
    return paddr + kernel_base_vaddr;
}

pub fn virtToPhys(vaddr: u64) u64 {
    const kernel_base_vaddr: u64 = @intCast(@intFromPtr(&_kernel_base_vaddr));
    return vaddr - kernel_base_vaddr;
}

pub fn pml4_index(vaddr: u64) u9 {
    return @truncate(vaddr >> @intFromEnum(PageLevelShift.PML4));
}

fn pdpt_index(vaddr: u64) u9 {
    return @truncate(vaddr >> @intFromEnum(PageLevelShift.PDPT));
}

fn pd_index(vaddr: u64) u9 {
    return @truncate(vaddr >> @intFromEnum(PageLevelShift.PD));
}

fn pt_index(vaddr: u64) u9 {
    return @truncate(vaddr >> @intFromEnum(PageLevelShift.PT));
}

pub fn read_cr3() u64 {
    var value: u64 = 0;
    asm volatile ("mov %%cr3, %[out]"
        : [out] "=r" (value),
    );
    return @intCast(value);
}

pub fn write_cr3(pml4: [*]PageEntry) void {
    const phys_addr: u64 = @intFromPtr(pml4);
    asm volatile ("mov %[value], %%cr3"
        :
        : [value] "r" (phys_addr),
        : .{ .memory = true });
}

/// Maps a region with the fewest possible page entries by prefering larger pages
pub fn physMapRegion(
    start_paddr: u64,
    end_paddr: u64,
    allocator: std.mem.Allocator,
) void {
    const page4K = @intFromEnum(PageSize.Page4K);
    const page2M = @intFromEnum(PageSize.Page2M);
    const page1G = @intFromEnum(PageSize.Page1G);

    std.debug.assert(end_paddr > start_paddr);
    std.debug.assert(std.mem.isAligned(start_paddr, page4K));
    std.debug.assert(std.mem.isAligned(end_paddr, page4K));

    const vaddr_start = physToVirt(start_paddr);

    const vaddr_end = physToVirt(end_paddr);
    std.debug.assert(vaddr_end > vaddr_start);

    const pml4_paddr = read_cr3() & ~@as(u64, 0xfff);
    const pml4_vaddr = physToVirt(pml4_paddr);

    var paddr = start_paddr;
    while (paddr < end_paddr) {
        const remaining = end_paddr - paddr;
        const chosen_size: u64 = blk: {
            if (std.mem.isAligned(paddr, page1G) and remaining >= page1G) break :blk page1G;
            if (std.mem.isAligned(paddr, page2M) and remaining >= page2M) break :blk page2M;
            break :blk page4K;
        };
        const size: PageSize = @enumFromInt(chosen_size);

        mapPage(
            @ptrFromInt(pml4_vaddr),
            paddr,
            physToVirt(paddr),
            RW.ReadWrite,
            User.Supervisor,
            size,
            allocator,
        );

        paddr += chosen_size;
    }
}

pub fn mapPage(
    pml4: [*]PML4Entry,
    paddr: u64,
    vaddr: u64,
    rw: RW,
    user: User,
    page_size: PageSize,
    allocator: std.mem.Allocator,
) void {
    std.debug.assert(std.mem.isAligned(
        paddr,
        PAGE_ALIGN.toByteUnits(),
    ));
    std.debug.assert(std.mem.isAligned(
        vaddr,
        PAGE_ALIGN.toByteUnits(),
    ));

    const default_flags = PageEntry{
        .present = false,
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

    std.debug.assert(pml4_idx < 512);
    std.debug.assert(pdpt_idx < 512);
    std.debug.assert(pd_idx < 512);
    std.debug.assert(pt_idx < 512);

    var pdpt_entry = &pml4[pml4_idx];
    if (!pdpt_entry.present) {
        const new_pdpt: []align(PAGE_ALIGN.toByteUnits()) PDPTEntry = allocator.alignedAlloc(
            PDPTEntry,
            PAGE_ALIGN,
            PAGE_TABLE_SIZE,
        ) catch @panic("Went OOM maping pages!");
        @memset(new_pdpt, default_flags);
        pdpt_entry.* = flags;
        pdpt_entry.setPaddr(@intCast(virtToPhys(
            @intFromPtr(new_pdpt.ptr)
        )));
    }
    const pdpt: [*]PDPTEntry = @ptrFromInt(physToVirt(
        pdpt_entry.getPaddr()
    ));

    if (page_size == .Page1G) {
        var entry = &pdpt[pdpt_idx];
        entry.* = flags;
        entry.huge_page = true;
        entry.setPaddr(paddr);
        return;
    }

    var pd_entry = &pdpt[pdpt_idx];
    if (!pd_entry.present) {
        const new_pd: []align(PAGE_ALIGN.toByteUnits()) PDEntry = allocator.alignedAlloc(
            PDEntry,
            PAGE_ALIGN,
            PAGE_TABLE_SIZE,
        ) catch @panic("Went OOM maping pages!");
        @memset(new_pd, default_flags);
        pd_entry.* = flags;
        pd_entry.setPaddr(@intCast(virtToPhys(
            @intFromPtr(new_pd.ptr)
        )));
    }
    const pd: [*]PDEntry = @ptrFromInt(physToVirt(
        pd_entry.getPaddr()
    ));

    if (page_size == .Page2M) {
        var entry = &pd[pd_idx];
        entry.* = flags;
        entry.huge_page = true;
        entry.setPaddr(paddr);
        return;
    }

    var pt_entry = &pd[pd_idx];
    if (!pt_entry.present) {
        const new_pt: []align(PAGE_ALIGN.toByteUnits()) PTEntry = allocator.alignedAlloc(
            PTEntry,
            PAGE_ALIGN,
            PAGE_TABLE_SIZE,
        ) catch @panic("Went OOM maping pages!");
        @memset(new_pt, default_flags);
        pt_entry.* = flags;
        pt_entry.setPaddr(@intCast(virtToPhys(
            @intFromPtr(new_pt.ptr)
        )));
    }
    const pt: [*]PTEntry = @ptrFromInt(physToVirt(
        pt_entry.getPaddr()
    ));

    pt[pt_idx] = flags;
    pt[pt_idx].setPaddr(@intCast(paddr));
}
