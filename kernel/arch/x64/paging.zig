const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const interrupts = zag.arch.x64.interrupts;
const paging = zag.memory.paging;
const physmap = zag.memory.address.AddrSpacePartition.physmap;
const pmm = zag.memory.pmm;

const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const SpinLock = zag.sched.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;

// TLB shootdown: per-core pending invalidation addresses.
// Each core checks its slot before returning to userspace.
var shootdown_lock: SpinLock = .{};
var shootdown_addr: u64 = 0;

/// IPI handler for TLB shootdown: invalidate the requested address.
/// endOfInterrupt is called by dispatchInterrupt for .external vectors.
pub fn tlbShootdownHandler(_: *cpu.Context) void {
    cpu.invlpg(@atomicLoad(u64, &shootdown_addr, .acquire));
}

/// Flush a user virtual address from all cores' TLBs.
/// The IPI is fire-and-forget: remote cores may have interrupts disabled
/// (e.g. mid-syscall), but the IPI will be delivered before any userspace
/// instruction executes (the pending interrupt fires on iret).  This is
/// safe because the physical page is only freed after this function
/// returns, and the remote core cannot touch the old mapping from
/// userspace until after the IPI handler runs.
fn flushRemoteTlb(virt_addr: u64) void {
    const core_count = apic.coreCount();
    if (core_count <= 1) return;

    const self_id = apic.coreID();

    shootdown_lock.lock();
    defer shootdown_lock.unlock();

    @atomicStore(u64, &shootdown_addr, virt_addr, .release);

    const vec = @intFromEnum(interrupts.IntVecs.tlb_shootdown);
    for (apic.lapics.?, 0..) |la, i| {
        if (i == self_id) continue;
        apic.sendIpi(@intCast(la.apic_id), vec);
    }
}

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
        std.debug.assert(std.mem.isAligned(paddr.addr, paging.PAGE4K));
        self.addr = @intCast(paddr.addr >> L1SH);
    }

    pub fn getPAddr(self: *const PageEntry) PAddr {
        const addr = @as(u64, self.addr) << L1SH;
        return PAddr.fromInt(addr);
    }
};

const DEFAULT_PAGE_ENTRY = PageEntry{};

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

pub fn dropIdentityMapping() void {
    const root_phys = getAddrSpaceRoot();
    const root_virt = VAddr.fromPAddr(root_phys, null);
    const root = root_virt.getPtr([*]PageEntry);

    for (0..256) |i| {
        root[i] = DEFAULT_PAGE_ENTRY;
    }

    cpu.writeCr3(root_phys.addr);
}

pub fn mapPage(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    perms: MemoryPerms,
) !void {
    std.debug.assert(std.mem.isAligned(phys.addr, paging.PAGE4K));
    std.debug.assert(std.mem.isAligned(virt.addr, paging.PAGE4K));

    const pmm_iface = pmm.global_pmm.?.allocator();

    const user_accessible = perms.privilege_perm == .user;
    const writable = perms.write_perm == .write;
    const not_executable = perms.execute_perm == .no_execute;
    const wc = perms.cache_perm == .write_combining;
    const not_cacheable = perms.cache_perm == .not_cacheable;
    const write_through = perms.cache_perm == .write_through or wc;
    const global = perms.global_perm == .global;

    const parent_entry = PageEntry{
        .present = true,
        .writable = true,
        .user_accessible = user_accessible,
    };

    // For L1 leaf entries, bit 7 (huge_page) is the PAT index bit
    const leaf_entry = PageEntry{
        .present = true,
        .writable = writable,
        .user_accessible = user_accessible,
        .write_through = write_through,
        .not_cacheable = not_cacheable,
        .huge_page = wc,
        .global = global,
        .not_executable = not_executable,
    };

    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[PAGE_ENTRY_TABLE_SIZE]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) {
            const new_page = try pmm_iface.create(paging.PageMem(.page4k));
            @memset(&new_page.mem, 0);
            const new_virt = VAddr.fromInt(@intFromPtr(new_page));
            const new_phys = PAddr.fromVAddr(new_virt, null);
            entry.* = parent_entry;
            entry.setPAddr(new_phys);
        }
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    l1_entry.* = leaf_entry;
    l1_entry.setPAddr(phys);
}

pub fn mapPageBoot(
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
    const wc = perms.cache_perm == .write_combining;
    const not_cacheable = perms.cache_perm == .not_cacheable;
    const write_through = perms.cache_perm == .write_through or wc;
    const global = perms.global_perm == .global;

    const parent_entry = PageEntry{
        .present = true,
        .writable = true,
        .user_accessible = user_accessible,
    };

    // For L1 leaf entries, bit 7 (huge_page) is the PAT index bit
    const leaf_entry = PageEntry{
        .present = true,
        .writable = writable,
        .user_accessible = user_accessible,
        .write_through = write_through,
        .not_cacheable = not_cacheable,
        .huge_page = wc,
        .global = global,
        .not_executable = not_executable,
    };

    const l4_idx = l4Idx(virt);
    const l3_idx = l3Idx(virt);
    const l2_idx = l2Idx(virt);
    const l1_idx = l1Idx(virt);

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
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[PAGE_ENTRY_TABLE_SIZE]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) return null;
        if (entry.huge_page) return null;
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    if (!l1_entry.present) return null;
    const phys = l1_entry.getPAddr();
    l1_entry.* = DEFAULT_PAGE_ENTRY;
    cpu.invlpg(virt.addr);

    // User-space pages may be cached in other cores' TLBs.  Flush them
    // so that a freed physical page cannot be read through a stale TLB
    // entry on a remote core.
    const user_end = zag.memory.address.AddrSpacePartition.user.end;
    if (virt.addr < user_end) {
        flushRemoteTlb(virt.addr);
    }

    return phys;
}

pub fn freeUserAddrSpace(addr_space_root: PAddr) void {
    const pmm_iface = pmm.global_pmm.?.allocator();
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    const root: *[PAGE_ENTRY_TABLE_SIZE]PageEntry = @ptrFromInt(root_virt.addr);

    for (root[0..256]) |*l4_entry| {
        if (!l4_entry.present) continue;
        std.debug.assert(!l4_entry.huge_page);
        const l3_table = entryToTable(l4_entry);

        for (l3_table) |*l3_entry| {
            if (!l3_entry.present) continue;
            std.debug.assert(!l3_entry.huge_page);
            const l2_table = entryToTable(l3_entry);

            for (l2_table) |*l2_entry| {
                if (!l2_entry.present) continue;
                std.debug.assert(!l2_entry.huge_page);
                const l1_table = entryToTable(l2_entry);

                for (l1_table) |*l1_entry| {
                    if (!l1_entry.present) continue;
                    freePhysPage(l1_entry.getPAddr(), pmm_iface);
                }
                freeTablePage(l1_table, pmm_iface);
            }
            freeTablePage(l2_table, pmm_iface);
        }
        freeTablePage(l3_table, pmm_iface);
    }
    freeTablePage(root, pmm_iface);
}

pub fn updatePagePerms(
    addr_space_root: PAddr,
    virt: VAddr,
    new_perms: MemoryPerms,
) void {
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[PAGE_ENTRY_TABLE_SIZE]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) return;
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    if (!l1_entry.present) return;

    l1_entry.writable = new_perms.write_perm == .write;
    l1_entry.not_executable = new_perms.execute_perm == .no_execute;
    const wc = new_perms.cache_perm == .write_combining;
    l1_entry.not_cacheable = new_perms.cache_perm == .not_cacheable;
    l1_entry.write_through = new_perms.cache_perm == .write_through or wc;
    l1_entry.huge_page = wc;
    l1_entry.user_accessible = new_perms.privilege_perm == .user;

    cpu.invlpg(virt.addr);

    // User-space permission changes must be visible on all cores.
    // Without this, a remote core's stale TLB entry retains the old
    // permissions (e.g. writable) after they have been revoked.
    const user_end = zag.memory.address.AddrSpacePartition.user.end;
    if (virt.addr < user_end) {
        flushRemoteTlb(virt.addr);
    }
}

pub fn resolveVaddr(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[PAGE_ENTRY_TABLE_SIZE]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) return null;
        if (entry.huge_page) return null;
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    if (!l1_entry.present) return null;
    return l1_entry.getPAddr();
}

fn entryToTable(entry: *const PageEntry) *[PAGE_ENTRY_TABLE_SIZE]PageEntry {
    const virt = VAddr.fromPAddr(entry.getPAddr(), null);
    return @ptrFromInt(virt.addr);
}

fn freePhysPage(paddr: PAddr, pmm_iface: std.mem.Allocator) void {
    const virt = VAddr.fromPAddr(paddr, null);
    const page: *paging.PageMem(.page4k) = @ptrFromInt(virt.addr);
    pmm_iface.destroy(page);
}

fn freeTablePage(table: *[PAGE_ENTRY_TABLE_SIZE]PageEntry, pmm_iface: std.mem.Allocator) void {
    const page: *paging.PageMem(.page4k) = @ptrCast(@alignCast(table));
    pmm_iface.destroy(page);
}
