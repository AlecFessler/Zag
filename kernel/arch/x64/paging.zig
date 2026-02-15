const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const paging = zag.memory.paging;
const physmap = zag.memory.address.AddrSpacePartition.physmap;

const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const VAddr = zag.memory.address.VAddr;

pub const PageEntry = packed struct(u64) {
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

pub fn copyKernelMappings(root: VAddr) void {
    const src_root_phys = getAddrSpaceRoot();
    const src_root_virt = VAddr.fromPAddr(src_root_phys, null);
    const src = src_root_virt.getPtr([*]PageEntry);
    const dst = root.getPtr([*]PageEntry);

    for (256..PAGE_ENTRY_TABLE_SIZE) |i| {
        dst[i] = src[i];
    }
}

pub fn dropIdentityAddrSpace() void {
    const root_phys = getAddrSpaceRoot();
    const root_virt = VAddr.fromPAddr(root_phys, null);
    const root = root_virt.getPtr([*]PageEntry);

    for (0..256) |i| {
        root[i] = PageEntry{
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
            .not_executable = false,
        };
    }

    cpu.writeCr3(root_phys.addr);
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
            const new_entry: []align(paging.PAGE4K) PageEntry = try allocator.alignedAlloc(
                PageEntry,
                paging.pageAlign(.page4k),
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
            else => unreachable,
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

pub fn unmapPage(
    addr_space_root: VAddr,
    virt: VAddr,
    size: PageSize,
) ?PAddr {
    const use_physmap = physmap.contains(addr_space_root.addr);
    var table: *[PAGE_ENTRY_TABLE_SIZE]PageEntry = @ptrFromInt(addr_space_root.addr);

    const indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt), l1Idx(virt) };
    const sizes = [_]PageSize{ .page1g, .page2m, .page4k };

    for (0..3) |i| {
        const entry = &table[indices[i]];
        if (!entry.present) return null;

        if (size == sizes[i] and (entry.huge_page or size == .page4k)) {
            const paddr = entry.getPAddr();
            entry.* = DEFAULT_PAGE_ENTRY;
            return paddr;
        }

        if (entry.huge_page) return null;

        var next_virt: VAddr = undefined;
        if (use_physmap) {
            next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        } else {
            next_virt = VAddr.fromPAddr(entry.getPAddr(), 0);
        }
        table = @ptrFromInt(next_virt.addr);
    }

    const entry = &table[indices[3]];
    if (!entry.present) return null;
    const paddr = entry.getPAddr();
    entry.* = DEFAULT_PAGE_ENTRY;
    return paddr;
}

pub fn freeUserAddrSpace(
    addr_space_root: VAddr,
    page_allocator: std.mem.Allocator,
) void {
    const root: *[PAGE_ENTRY_TABLE_SIZE]PageEntry = @ptrFromInt(addr_space_root.addr);

    for (root[0..256]) |*l4_entry| {
        if (!l4_entry.present) continue;
        const l3_table = entryToTable(l4_entry);

        for (l3_table) |*l3_entry| {
            if (!l3_entry.present) continue;
            if (l3_entry.huge_page) {
                freePhysPage(l3_entry.getPAddr(), paging.PAGE1G, page_allocator);
                continue;
            }
            const l2_table = entryToTable(l3_entry);

            for (l2_table) |*l2_entry| {
                if (!l2_entry.present) continue;
                if (l2_entry.huge_page) {
                    freePhysPage(l2_entry.getPAddr(), paging.PAGE2M, page_allocator);
                    continue;
                }
                const l1_table = entryToTable(l2_entry);

                for (l1_table) |*l1_entry| {
                    if (!l1_entry.present) continue;
                    freePhysPage(l1_entry.getPAddr(), paging.PAGE4K, page_allocator);
                }
                freeTablePage(l1_table, page_allocator);
            }
            freeTablePage(l2_table, page_allocator);
        }
        freeTablePage(l3_table, page_allocator);
    }
    freeTablePage(root, page_allocator);
}

fn entryToTable(entry: *const PageEntry) *[PAGE_ENTRY_TABLE_SIZE]PageEntry {
    const virt = VAddr.fromPAddr(entry.getPAddr(), null);
    return @ptrFromInt(virt.addr);
}

fn freePhysPage(paddr: PAddr, size: u64, page_allocator: std.mem.Allocator) void {
    const virt = VAddr.fromPAddr(paddr, null);
    const ptr: [*]align(paging.PAGE4K) u8 = @ptrFromInt(virt.addr);
    page_allocator.free(ptr[0..size]);
}

fn freeTablePage(table: *[PAGE_ENTRY_TABLE_SIZE]PageEntry, page_allocator: std.mem.Allocator) void {
    const ptr: [*]align(paging.PAGE4K) PageEntry = @alignCast(@as([*]PageEntry, @ptrCast(table)));
    page_allocator.free(ptr[0..PAGE_ENTRY_TABLE_SIZE]);
}
