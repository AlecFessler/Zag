const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const MMIO_PERMS: MemoryPerms = .{
    .write_perm = .write,
    .execute_perm = .no_execute,
    .cache_perm = .not_cacheable,
    .global_perm = .not_global,
    .privilege_perm = .kernel,
};

const MMIO_DEV_TABLE_BASE = 0x0000;
const MMIO_CMD_BUF_BASE = 0x0008;
const MMIO_EVT_LOG_BASE = 0x0010;
const MMIO_CONTROL = 0x0018;
const MMIO_CMD_BUF_HEAD = 0x2000;
const MMIO_CMD_BUF_TAIL = 0x2008;

const CTRL_IOMMU_EN: u64 = 1 << 0;
const CTRL_CMD_BUF_EN: u64 = 1 << 12;
const CTRL_EVT_LOG_EN: u64 = 1 << 2;
const CTRL_COHERENT_EN: u64 = 1 << 26;

const AMDVI_IR: u64 = 1 << 61;
const AMDVI_IW: u64 = 1 << 62;
const AMDVI_RW: u64 = AMDVI_IR | AMDVI_IW;
const AMDVI_ADDR_MASK: u64 = 0xFFFFFFFFF000;

const MAX_IOMMU_UNITS = 4;
const MAX_ALIASES = 128;

const IommuUnit = struct {
    base: u64 = 0,
    dev_table_phys: PAddr = PAddr.fromInt(0),
    dev_table_virt: VAddr = VAddr.fromInt(0),
    dev_table_size: u64 = 0,
    cmd_buf_phys: PAddr = PAddr.fromInt(0),
    cmd_buf_virt: VAddr = VAddr.fromInt(0),
    active: bool = false,

    fn readReg64(self: *const IommuUnit, offset: u32) u64 {
        const ptr: *const volatile u64 = @ptrFromInt(self.base + offset);
        return ptr.*;
    }

    fn writeReg64(self: *const IommuUnit, offset: u32, value: u64) void {
        const ptr: *volatile u64 = @ptrFromInt(self.base + offset);
        ptr.* = value;
    }

    fn issueCommand(self: *const IommuUnit, lo: u64, hi: u64) void {
        const tail = self.readReg64(MMIO_CMD_BUF_TAIL);
        const cmd_ptr: [*]volatile u64 = @ptrFromInt(self.cmd_buf_virt.addr + (tail & 0xFFF));
        cmd_ptr[0] = lo;
        cmd_ptr[1] = hi;
        self.writeReg64(MMIO_CMD_BUF_TAIL, (tail + 16) & 0xFFF);
    }

    fn invalidateDeviceEntry(self: *const IommuUnit, device_id: u16) void {
        self.issueCommand(0x02 | (@as(u64, device_id) << 16), 0);
    }

    fn invalidateIotlbDomain(self: *const IommuUnit, domain_id: u16) void {
        self.issueCommand(0x03 | (@as(u64, 1) << 20) | (@as(u64, domain_id) << 32), 0);
    }
};

const AliasEntry = struct {
    source: u16 = 0,
    alias: u16 = 0,
};

var units: [MAX_IOMMU_UNITS]IommuUnit = .{IommuUnit{}} ** MAX_IOMMU_UNITS;
var unit_count: u32 = 0;
var aliases: [MAX_ALIASES]AliasEntry = .{AliasEntry{}} ** MAX_ALIASES;
var alias_count: u32 = 0;

fn allocZeroedPage() !struct { phys: PAddr, virt: VAddr } {
    const pmm_iface = pmm.global_pmm.?.allocator();
    const page = try pmm_iface.create(paging.PageMem(.page4k));
    @memset(std.mem.asBytes(page), 0);
    const virt = VAddr.fromInt(@intFromPtr(page));
    const phys = PAddr.fromVAddr(virt, null);
    return .{ .phys = phys, .virt = virt };
}

fn lookupAlias(bdf: u16) u16 {
    for (aliases[0..alias_count]) |entry| {
        if (entry.source == bdf) return entry.alias;
    }
    return bdf;
}

pub fn addAlias(source: u16, alias: u16) void {
    if (alias_count >= MAX_ALIASES) return;
    aliases[alias_count] = .{ .source = source, .alias = alias };
    alias_count += 1;
}

pub fn init(reg_base_phys: PAddr) !void {
    if (unit_count >= MAX_IOMMU_UNITS) return;

    var unit = &units[unit_count];

    const num_mmio_pages: u32 = 4;
    var i: u32 = 0;
    while (i < num_mmio_pages) : (i += 1) {
        const page_phys = PAddr.fromInt(reg_base_phys.addr + @as(u64, i) * paging.PAGE4K);
        const page_virt = VAddr.fromPAddr(page_phys, null);
        arch.mapPage(memory_init.kernel_addr_space_root, page_phys, page_virt, MMIO_PERMS) catch continue;
    }
    unit.base = VAddr.fromPAddr(reg_base_phys, null).addr;

    // Full device table: 65536 entries * 32 bytes = 2MB = 512 pages.
    const dt_pages: u32 = 512;
    const dt_size = @as(u64, dt_pages) * paging.PAGE4K;
    const pmm_iface = pmm.global_pmm.?.allocator();
    const dt_mem = pmm_iface.rawAlloc(
        dt_size,
        std.mem.Alignment.fromByteUnits(paging.PAGE4K),
        0,
    ) orelse return error.OutOfMemory;
    @memset(dt_mem[0..dt_size], 0);
    // Initialize all DTEs with V=1, TV=1 to block DMA by default
    {
        var dte_idx: u64 = 0;
        while (dte_idx < 65536) : (dte_idx += 1) {
            const dte: *volatile u64 = @ptrFromInt(@intFromPtr(dt_mem) + dte_idx * 32);
            dte.* = 0x3; // V=1, TV=1, no page table = all faults
        }
    }
    const dt_virt = VAddr.fromInt(@intFromPtr(dt_mem));
    unit.dev_table_phys = PAddr.fromVAddr(dt_virt, null);
    unit.dev_table_virt = dt_virt;
    unit.dev_table_size = dt_size;

    const dt_entries = dt_size / 32;
    const dt_size_bits: u64 = std.math.log2(dt_entries) - 1;
    unit.writeReg64(MMIO_DEV_TABLE_BASE, unit.dev_table_phys.addr | (dt_size_bits & 0x1FF));

    const cmd = try allocZeroedPage();
    unit.cmd_buf_phys = cmd.phys;
    unit.cmd_buf_virt = cmd.virt;
    const cmd_len_bits: u64 = 8;
    unit.writeReg64(MMIO_CMD_BUF_BASE, unit.cmd_buf_phys.addr | (cmd_len_bits << 56));

    const evt = try allocZeroedPage();
    const evt_len_bits: u64 = 8;
    unit.writeReg64(MMIO_EVT_LOG_BASE, evt.phys.addr | (evt_len_bits << 56));

    var ctrl = unit.readReg64(MMIO_CONTROL);
    ctrl |= CTRL_IOMMU_EN | CTRL_CMD_BUF_EN | CTRL_EVT_LOG_EN | CTRL_COHERENT_EN;
    unit.writeReg64(MMIO_CONTROL, ctrl);

    unit.active = true;
    unit_count += 1;
}

pub fn setupDevice(device: *DeviceRegion) !void {
    if (unit_count == 0) return;

    const bdf = @as(u16, device.pci_bus) << 8 | @as(u16, device.pci_dev) << 3 | @as(u16, device.pci_func);
    const device_id = lookupAlias(bdf);
    const entry_offset = @as(u64, device_id) * 32;

    const pt = try allocZeroedPage();
    device.dma_page_table_root = pt.phys;

    const mode: u64 = 4;
    const qw0 = 0x3 | (mode << 9) | (pt.phys.addr & AMDVI_ADDR_MASK) | AMDVI_RW;
    const qw1 = @as(u64, device_id);

    for (units[0..unit_count]) |*unit| {
        if (!unit.active) continue;

        // Write DTE at alias index
        if (entry_offset + 32 <= unit.dev_table_size) {
            const entry_base: [*]volatile u64 = @ptrFromInt(unit.dev_table_virt.addr + entry_offset);
            entry_base[0] = qw0;
            entry_base[1] = qw1;
            entry_base[2] = 0;
            entry_base[3] = 0;
            unit.invalidateDeviceEntry(device_id);
            unit.invalidateIotlbDomain(device_id);
        }

        // Also write DTE at original BDF if aliased
        if (device_id != bdf) {
            const bdf_offset = @as(u64, bdf) * 32;
            if (bdf_offset + 32 <= unit.dev_table_size) {
                const bdf_entry: [*]volatile u64 = @ptrFromInt(unit.dev_table_virt.addr + bdf_offset);
                bdf_entry[0] = qw0;
                bdf_entry[1] = qw1;
                bdf_entry[2] = 0;
                bdf_entry[3] = 0;
                unit.invalidateDeviceEntry(bdf);
                unit.invalidateIotlbDomain(bdf);
            }
        }
    }
}

fn amdviNonLeaf(phys_addr: u64, next_level: u64) u64 {
    return (phys_addr & AMDVI_ADDR_MASK) | (next_level << 9) | AMDVI_RW | 0x1;
}

fn amdviLeaf(phys_addr: u64) u64 {
    return (phys_addr & AMDVI_ADDR_MASK) | AMDVI_RW | 0x1;
}

fn amdviPresent(entry: u64) bool {
    return (entry & 0x1) != 0;
}

pub fn mapDmaPage(device: *DeviceRegion, dma_addr: u64, phys: PAddr) !void {
    if (unit_count == 0 or device.dma_page_table_root.addr == 0) return error.NotSetup;

    const pml4_virt = VAddr.fromPAddr(device.dma_page_table_root, null);
    const pml4: *[512]u64 = @ptrFromInt(pml4_virt.addr);

    const pml4_idx: u9 = @truncate((dma_addr >> 39) & 0x1FF);
    const pdpt_idx: u9 = @truncate((dma_addr >> 30) & 0x1FF);
    const pd_idx: u9 = @truncate((dma_addr >> 21) & 0x1FF);
    const pt_idx: u9 = @truncate((dma_addr >> 12) & 0x1FF);

    if (!amdviPresent(pml4[pml4_idx])) {
        const page = try allocZeroedPage();
        pml4[pml4_idx] = amdviNonLeaf(page.phys.addr, 3);
    }
    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & AMDVI_ADDR_MASK), null).addr);

    if (!amdviPresent(pdpt[pdpt_idx])) {
        const page = try allocZeroedPage();
        pdpt[pdpt_idx] = amdviNonLeaf(page.phys.addr, 2);
    }
    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & AMDVI_ADDR_MASK), null).addr);

    if (!amdviPresent(pd[pd_idx])) {
        const page = try allocZeroedPage();
        pd[pd_idx] = amdviNonLeaf(page.phys.addr, 1);
    }
    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & AMDVI_ADDR_MASK), null).addr);

    pt[pt_idx] = amdviLeaf(phys.addr);
}

pub fn unmapDmaPage(device: *DeviceRegion, dma_addr: u64) void {
    if (unit_count == 0 or device.dma_page_table_root.addr == 0) return;

    const pml4_virt = VAddr.fromPAddr(device.dma_page_table_root, null);
    const pml4: *[512]u64 = @ptrFromInt(pml4_virt.addr);
    const pml4_idx: u9 = @truncate((dma_addr >> 39) & 0x1FF);
    if (!amdviPresent(pml4[pml4_idx])) return;

    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & AMDVI_ADDR_MASK), null).addr);
    const pdpt_idx: u9 = @truncate((dma_addr >> 30) & 0x1FF);
    if (!amdviPresent(pdpt[pdpt_idx])) return;

    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & AMDVI_ADDR_MASK), null).addr);
    const pd_idx: u9 = @truncate((dma_addr >> 21) & 0x1FF);
    if (!amdviPresent(pd[pd_idx])) return;

    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & AMDVI_ADDR_MASK), null).addr);
    const pt_idx: u9 = @truncate((dma_addr >> 12) & 0x1FF);
    pt[pt_idx] = 0;
}

pub fn flushDevice(device: *const DeviceRegion) void {
    if (unit_count == 0) return;
    const bdf = @as(u16, device.pci_bus) << 8 | @as(u16, device.pci_dev) << 3 | @as(u16, device.pci_func);
    const domain_id = lookupAlias(bdf);
    for (units[0..unit_count]) |*unit| {
        if (unit.active) unit.invalidateIotlbDomain(domain_id);
    }
}

pub fn isAvailable() bool {
    return unit_count > 0;
}
