const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const paging = zag.memory.paging;
const physmap = zag.memory.address.AddrSpacePartition.physmap;

const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const VAddr = zag.memory.address.VAddr;

const PageEntry = packed struct(u64) {
    present: bool = false,
    writable: bool = false,
    user_accessible: bool = false,
    write_through: bool = false,
    not_cacheable: bool = false,
    accessed: bool = false,
    dirty: bool = false,
    huge_page: bool = false,
    global: bool = false,
    ignored: u3 = 0,
    addr: u40 = 0,
    _res: u11 = 0,
    not_executable: bool = false,

    pub fn setPAddr(self: *PageEntry, paddr: PAddr) void {
        std.debug.assert(std.mem.isAligned(paddr.addr, paging.pageAlign(.page4k).toByteUnits()));
        self.addr = @intCast(paddr.addr >> L1SH);
    }

    pub fn getPAddr(self: *const PageEntry) PAddr {
        const addr = @as(u64, self.addr) << L1SH;
        return PAddr.fromInt(addr);
    }
};

const DEFAULT_PAGE_ENTRY = PageEntry{
    .present = false,
    .writable = false,
    .user_accessible = false,
    .write_through = false,
    .not_cacheable = false,
    .accessed = false,
    .dirty = false,
    .huge_page = false,
    .global = false,
    .ignored = 0,
    .addr = 0,
    ._res = 0,
    .not_executable = false,
};

const PAGE_ENTRY_TABLE_SIZE = 512;

const L4SH: u6 = 39;
const L3SH: u6 = 30;
const L2SH: u6 = 21;
const L1SH: u6 = 12;

fn l4Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> L4SH);
}

fn l3Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> L3SH);
}

fn l2Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> L2SH);
}

fn l1Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> L1SH);
}

pub fn getAddrSpaceRoot() PAddr {
    const cr3 = cpu.readCr3();
    const mask: u64 = 0xFFF;
    return PAddr.fromInt(cr3 & ~mask);
}

pub fn swapAddrSpace(root: PAddr) void {
    cpu.writeCr3(root.addr);
}

pub fn mapPage(
    addr_space_root: VAddr,
    phys: PAddr,
    virt: VAddr,
    size: PageSize,
    perms: MemoryPerms,
    allocator: std.mem.Allocator,
) !void {
    std.debug.assert(std.mem.isAligned(phys.addr, paging.pageAlign(size).toByteUnits()));
    std.debug.assert(std.mem.isAligned(virt.addr, paging.pageAlign(size).toByteUnits()));

    const user_accessible = perms.privilege_perm == .user;
    const writable = perms.write_perm == .write;
    const not_executable = perms.execute_perm == .no_execute;
    const not_cacheable = perms.cache_perm == .not_cacheable;
    const write_through = perms.cache_perm == .write_through;
    const global = perms.global_perm == .global;

    const parent_entry = PageEntry{
        .present = true,
        .writable = true,
        .user_accessible = user_accessible,
        .write_through = false,
        .not_cacheable = false,
        .accessed = false,
        .dirty = false,
        .huge_page = false,
        .global = false,
        .ignored = 0,
        .addr = 0,
        .not_executable = false,
    };

    const leaf_entry = PageEntry{
        .present = true,
        .writable = writable,
        .user_accessible = user_accessible,
        .write_through = write_through,
        .not_cacheable = not_cacheable,
        .accessed = false,
        .dirty = false,
        .huge_page = false,
        .global = global,
        .ignored = 0,
        .addr = 0,
        .not_executable = not_executable,
    };

    const l4_idx = l4Idx(virt);
    const l3_idx = l3Idx(virt);
    const l2_idx = l2Idx(virt);
    const l1_idx = l1Idx(virt);

    std.debug.assert(l4_idx < PAGE_ENTRY_TABLE_SIZE);
    std.debug.assert(l3_idx < PAGE_ENTRY_TABLE_SIZE);
    std.debug.assert(l2_idx < PAGE_ENTRY_TABLE_SIZE);
    std.debug.assert(l1_idx < PAGE_ENTRY_TABLE_SIZE);

    var table: *[PAGE_ENTRY_TABLE_SIZE]PageEntry = @ptrFromInt(addr_space_root.addr);
    var entry = &table[l4_idx];
    var level_entry_size: PageSize = .page1g;
    const use_physmap = physmap.contains(addr_space_root.addr);

    for (0..3) |i| {
        if (!entry.present) {
            const page4k_align = paging.PageAlign(.page4k);
            const new_entry: []align(page4k_align.toByteUnits()) PageEntry = try allocator.alignedAlloc(
                PageEntry,
                page4k_align,
                PAGE_ENTRY_TABLE_SIZE,
            );
            @memset(new_entry, DEFAULT_PAGE_ENTRY);
            entry.* = parent_entry;

            const new_entry_virt = VAddr.fromInt(@intFromPtr(new_entry.ptr));
            var new_entry_phys: PAddr = undefined;
            if (use_physmap) {
                new_entry_phys = PAddr.fromVAddr(new_entry_virt, null);
            } else {
                new_entry_phys = PAddr.fromVAddr(new_entry_virt, 0);
            }
            entry.setPAddr(new_entry_phys);
        }

        var entry_virt: VAddr = undefined;
        if (use_physmap) {
            entry_virt = VAddr.fromPAddr(entry.getPAddr(), null);
            std.debug.assert(physmap.contains(entry_virt.addr));
        } else {
            entry_virt = VAddr.fromPAddr(entry.getPAddr(), 0);
            std.debug.assert(!physmap.contains(entry_virt.addr));
        }

        table = @ptrFromInt(entry_virt.addr);
        const idx = switch (i) {
            0 => l3_idx,
            1 => l2_idx,
            2 => l1_idx,
        };
        entry = &table[idx];

        if (size == level_entry_size) {
            entry.* = leaf_entry;
            if (level_entry_size != .page4k) entry.huge_page = true;
            entry.setPAddr(phys);
            return;
        }

        if (i == 0) {
            level_entry_size = .page2m;
        } else if (i == 1) {
            level_entry_size = .page4k;
        }
    }
}
