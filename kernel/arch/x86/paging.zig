const std = @import("std");
const vga = @import("vga.zig");

pub const AddressSpace = enum(u9) {
    /// Higher half direct mapping
    /// Includes the physmap at pml4 base
    /// And kernel text and data at _kernel_end linker symbol
    hhdm = 511,
    /// Kernel virtual memory mapping
    /// Used by the kernel vmm for allocating address space to allocators
    kvmm = 510,
};

pub const HHDMType = enum {
    kernel,
    physmap,
};

pub const PageSize = enum(u64) {
    Page4K = 4 * 1024,
    Page2M = 2 * 1024 * 1024,
    Page1G = 1 * 1024 * 1024 * 1024,
};

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

pub const PageEntry = packed struct {
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

    pub fn setPAddr(self: *PageEntry, paddr: PAddr) void {
        std.debug.assert(std.mem.isAligned(paddr.addr, PAGE_ALIGN.toByteUnits()));
        self.addr = @intCast(paddr.addr >> 12);
    }

    pub fn getPAddr(self: *const PageEntry) PAddr {
        const addr = @as(u64, self.addr) << 12;
        return PAddr.fromInt(addr);
    }
};

comptime {
    std.debug.assert(@sizeOf(PageEntry) == 8);
}

pub const PAddr = struct {
    addr: u64,

    pub fn fromInt(addr: u64) PAddr {
        return .{
            .addr = addr,
        };
    }

    pub fn fromVAddr(vaddr: VAddr, type_: HHDMType) PAddr {
        const base_vaddr = switch (type_) {
            .kernel => VAddr.fromInt(@intCast(@intFromPtr(&_kernel_base_vaddr))),
            .physmap => pml4SlotBase(@intFromEnum(AddressSpace.hhdm)),
        };
        const phys = vaddr.addr - base_vaddr.addr;
        return .{
            .addr = phys,
        };
    }

    pub fn getPtr(self: *const @This(), comptime type_: anytype) type_ {
        return @ptrFromInt(self.addr);
    }
};

pub const VAddr = struct {
    addr: u64,

    pub fn fromInt(addr: u64) VAddr {
        return .{
            .addr = addr,
        };
    }

    pub fn fromPAddr(paddr: PAddr, type_: HHDMType) VAddr {
        const base_vaddr = switch (type_) {
            .kernel => VAddr.fromInt(@intCast(@intFromPtr(&_kernel_base_vaddr))),
            .physmap => pml4SlotBase(@intFromEnum(AddressSpace.hhdm)),
        };
        const virt = paddr.addr + base_vaddr.addr;
        return .{
            .addr = virt,
        };
    }

    pub fn getPtr(self: *const @This(), comptime type_: anytype) type_ {
        return @ptrFromInt(self.addr);
    }

    pub fn remapHHDMType(self: *const @This(), from: HHDMType, to: HHDMType) VAddr {
        std.debug.assert(from != to);
        const paddr = PAddr.fromVAddr(self.*, from);
        return VAddr.fromPAddr(paddr, to);
    }
};

const PML4Entry = PageEntry;
const PDEntry = PageEntry;
const PDPTEntry = PageEntry;
const PTEntry = PageEntry;

pub const default_flags = PageEntry{
    .present = false,
    .rw = .Readonly,
    .user = .Supervisor,
    .write_through = false,
    .cache_disable = false,
    .accessed = false,
    .dirty = false,
    .huge_page = false,
    .global = false,
    .ignored = 0,
    .addr = 0,
    .reserved = 0,
    .nx = true,
};

pub const PAGE_ALIGN = std.mem.Alignment.fromByteUnits(@intFromEnum(PageSize.Page4K));

pub const PAGE_TABLE_SIZE = 512;

extern const _kernel_base_vaddr: u8;

pub fn mapPage(
    pml4: [*]PML4Entry,
    paddr: PAddr,
    vaddr: VAddr,
    rw: RW,
    nx: bool,
    user: User,
    page_size: PageSize,
    hhdm_type: HHDMType,
    allocator: std.mem.Allocator,
) void {
    std.debug.assert(std.mem.isAligned(
        paddr.addr,
        PAGE_ALIGN.toByteUnits(),
    ));
    std.debug.assert(std.mem.isAligned(
        vaddr.addr,
        PAGE_ALIGN.toByteUnits(),
    ));

    const flags = PageEntry{
        .present = true,
        .rw = .ReadWrite,
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
        const new_pdpt_vaddr = VAddr.fromInt(@intFromPtr(new_pdpt.ptr));
        const new_pdpt_paddr = PAddr.fromVAddr(new_pdpt_vaddr, hhdm_type);
        pdpt_entry.setPAddr(new_pdpt_paddr);
    }
    const pdpt_entry_vaddr = VAddr.fromPAddr(pdpt_entry.getPAddr(), hhdm_type);
    const pdpt = pdpt_entry_vaddr.getPtr([*]PDPTEntry);

    if (page_size == .Page1G) {
        var entry = &pdpt[pdpt_idx];
        entry.* = flags;
        entry.huge_page = true;
        entry.rw = rw;
        if (nx) entry.nx = true;
        entry.setPAddr(paddr);
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
        const new_pd_vaddr = VAddr.fromInt(@intFromPtr(new_pd.ptr));
        const new_pd_paddr = PAddr.fromVAddr(new_pd_vaddr, hhdm_type);
        pd_entry.setPAddr(new_pd_paddr);
    }
    const pd_entry_vaddr = VAddr.fromPAddr(pd_entry.getPAddr(), hhdm_type);
    const pd = pd_entry_vaddr.getPtr([*]PDEntry);

    if (page_size == .Page2M) {
        var entry = &pd[pd_idx];
        entry.* = flags;
        entry.huge_page = true;
        entry.rw = rw;
        if (nx) entry.nx = true;
        entry.setPAddr(paddr);
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
        const new_pt_vaddr = VAddr.fromInt(@intFromPtr(new_pt.ptr));
        const new_pt_paddr = PAddr.fromVAddr(new_pt_vaddr, hhdm_type);
        pt_entry.setPAddr(new_pt_paddr);
    }
    const pt_entry_vaddr = VAddr.fromPAddr(pt_entry.getPAddr(), hhdm_type);
    const pt = pt_entry_vaddr.getPtr([*]PTEntry);

    pt[pt_idx] = flags;
    pt[pt_idx].rw = rw;
    if (nx) pt[pt_idx].nx = true;
    pt[pt_idx].setPAddr(paddr);
}

pub fn PageMem(comptime page_size: PageSize) type {
    const size_bytes = @intFromEnum(page_size);
    return struct {
        mem: [size_bytes]u8 align(size_bytes),
    };
}

pub fn pml4SlotBase(slot: u9) VAddr {
    const raw: u64 = (@as(u64, slot) << 39);
    const base = if ((raw & 1 << 47) != 0) (raw | 0xFFFF000000000000) else raw;
    return VAddr.fromInt(base);
}

pub fn pml4_index(vaddr: VAddr) u9 {
    return @truncate(vaddr.addr >> @intFromEnum(PageLevelShift.PML4));
}

/// Maps a region with the fewest possible page entries by prefering larger pages
/// Needs to use .kernel hhdm region since it runs as apart of creating the new page tables
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
            RW.ReadWrite,
            true,
            User.Supervisor,
            @enumFromInt(chosen_size),
            .kernel,
            allocator,
        );

        paddr.addr += chosen_size;
    }
}

pub fn read_cr3() PAddr {
    var value: u64 = 0;
    asm volatile ("mov %%cr3, %[out]"
        : [out] "=r" (value),
    );
    return PAddr.fromInt(value);
}

pub fn write_cr3(pml4_paddr: PAddr) void {
    asm volatile ("mov %[value], %%cr3"
        :
        : [value] "r" (pml4_paddr.addr),
        : .{ .memory = true });
}

fn pd_index(vaddr: VAddr) u9 {
    return @truncate(vaddr.addr >> @intFromEnum(PageLevelShift.PD));
}

fn pdpt_index(vaddr: VAddr) u9 {
    return @truncate(vaddr.addr >> @intFromEnum(PageLevelShift.PDPT));
}

fn pt_index(vaddr: VAddr) u9 {
    return @truncate(vaddr.addr >> @intFromEnum(PageLevelShift.PT));
}
