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

const DeviceTableEntry = packed struct(u256) {
    valid: bool,
    translation_valid: bool,
    _res0: u5 = 0,
    _had: u2 = 0,
    paging_mode: u3 = 4,
    host_page_table_root: u40,
    _res1: u3 = 0,
    _sys: u6 = 0,
    ir: bool = true,
    iw: bool = true,
    _res2: u1 = 0,
    domain_id: u16,
    _res3: u48 = 0,
    _res4: u128 = 0,
};

var iommu_base: u64 = 0;
var dev_table_phys: PAddr = PAddr.fromInt(0);
var dev_table_virt: VAddr = VAddr.fromInt(0);
var dev_table_size: u64 = 0;
var cmd_buf_phys: PAddr = PAddr.fromInt(0);
var cmd_buf_virt: VAddr = VAddr.fromInt(0);
var initialized: bool = false;

fn readReg64(offset: u32) u64 {
    const ptr: *const volatile u64 = @ptrFromInt(iommu_base + offset);
    return ptr.*;
}

fn writeReg64(offset: u32, value: u64) void {
    const ptr: *volatile u64 = @ptrFromInt(iommu_base + offset);
    ptr.* = value;
}

fn allocZeroedPage() !struct { phys: PAddr, virt: VAddr } {
    const pmm_iface = pmm.global_pmm.?.allocator();
    const page = try pmm_iface.create(paging.PageMem(.page4k));
    @memset(std.mem.asBytes(page), 0);
    const virt = VAddr.fromInt(@intFromPtr(page));
    const phys = PAddr.fromVAddr(virt, null);
    return .{ .phys = phys, .virt = virt };
}

pub fn init(reg_base_phys: PAddr) !void {
    const num_mmio_pages: u32 = 4;
    var i: u32 = 0;
    while (i < num_mmio_pages) : (i += 1) {
        const page_phys = PAddr.fromInt(reg_base_phys.addr + @as(u64, i) * paging.PAGE4K);
        const page_virt = VAddr.fromPAddr(page_phys, null);
        arch.mapPage(memory_init.kernel_addr_space_root, page_phys, page_virt, MMIO_PERMS) catch continue;
    }
    iommu_base = VAddr.fromPAddr(reg_base_phys, null).addr;

    // Full device table: 65536 entries × 32 bytes = 2MB = 512 pages.
    // Must be physically contiguous since the IOMMU hardware walks it.
    const dt_pages: u32 = 512;
    dev_table_size = @as(u64, dt_pages) * paging.PAGE4K;
    const pmm_iface = pmm.global_pmm.?.allocator();
    const dt_mem = pmm_iface.rawAlloc(
        dev_table_size,
        std.mem.Alignment.fromByteUnits(paging.PAGE4K),
        0,
    ) orelse return error.OutOfMemory;
    @memset(dt_mem[0..dev_table_size], 0);
    const dt_virt = VAddr.fromInt(@intFromPtr(dt_mem));
    dev_table_phys = PAddr.fromVAddr(dt_virt, null);
    dev_table_virt = dt_virt;

    const dt_entries = dev_table_size / 32;
    const dt_size_bits: u64 = std.math.log2(dt_entries) - 1;
    writeReg64(MMIO_DEV_TABLE_BASE, dev_table_phys.addr | (dt_size_bits & 0x1FF));

    const cmd = try allocZeroedPage();
    cmd_buf_phys = cmd.phys;
    cmd_buf_virt = cmd.virt;
    const cmd_len_bits: u64 = 8;
    writeReg64(MMIO_CMD_BUF_BASE, cmd_buf_phys.addr | (cmd_len_bits << 56));

    const evt = try allocZeroedPage();
    const evt_len_bits: u64 = 8;
    writeReg64(MMIO_EVT_LOG_BASE, evt.phys.addr | (evt_len_bits << 56));

    var ctrl = readReg64(MMIO_CONTROL);
    ctrl |= CTRL_IOMMU_EN | CTRL_CMD_BUF_EN | CTRL_EVT_LOG_EN;
    writeReg64(MMIO_CONTROL, ctrl);

    initialized = true;
}

pub fn setupDevice(device: *DeviceRegion) !void {
    if (!initialized) return;

    const device_id = @as(u16, device.pci_bus) << 8 | @as(u16, device.pci_dev) << 3 | @as(u16, device.pci_func);
    const entry_offset = @as(u64, device_id) * 32;

    if (entry_offset + 32 > dev_table_size) return;

    const pt = try allocZeroedPage();
    device.dma_page_table_root = pt.phys;

    const entry_base: [*]volatile u64 = @ptrFromInt(dev_table_virt.addr + entry_offset);

    // DTE quadword 0:
    // [0] V=1, [1] TV=1, [8:7] HAD=0, [11:9] Mode=4,
    // [51:12] page table root, [61] IR=1, [62] IW=1
    const mode: u64 = 4;
    entry_base[0] = 0x3 | (mode << 9) | (pt.phys.addr & 0xFFFFFFFFF000) | AMDVI_RW;

    // DTE quadword 1: [15:0] DomainID
    entry_base[1] = @as(u64, device_id);

    // DTE quadwords 2-3: reserved, keep zero
    entry_base[2] = 0;
    entry_base[3] = 0;

    invalidateDeviceEntry(device_id);
    invalidateIotlb();
}

const AMDVI_IR: u64 = 1 << 61;
const AMDVI_IW: u64 = 1 << 62;
const AMDVI_RW: u64 = AMDVI_IR | AMDVI_IW;
const AMDVI_ADDR_MASK: u64 = 0xFFFFFFFFF000;

fn amdviNonLeaf(phys_addr: u64, next_level: u64) u64 {
    return (phys_addr & AMDVI_ADDR_MASK) | (next_level << 9) | AMDVI_RW | 0x3;
}

fn amdviLeaf(phys_addr: u64) u64 {
    return (phys_addr & AMDVI_ADDR_MASK) | AMDVI_RW | 0x3;
}

fn amdviPresent(entry: u64) bool {
    return (entry & 0x3) != 0;
}

pub fn mapDmaPage(device: *DeviceRegion, dma_addr: u64, phys: PAddr) !void {
    if (!initialized or device.dma_page_table_root.addr == 0) return error.NotSetup;

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
    if (!initialized or device.dma_page_table_root.addr == 0) return;

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

    invalidateIotlb();
}

fn issueCommand(lo: u64, hi: u64) void {
    const tail = readReg64(MMIO_CMD_BUF_TAIL);
    const cmd_ptr: [*]volatile u64 = @ptrFromInt(cmd_buf_virt.addr + (tail & 0xFFF));
    cmd_ptr[0] = lo;
    cmd_ptr[1] = hi;
    writeReg64(MMIO_CMD_BUF_TAIL, (tail + 16) & 0xFFF);
}

pub fn invalidateDeviceEntry(device_id: u16) void {
    if (!initialized) return;
    // CMD_INVALIDATE_DEVTAB_ENTRY (type 0x02)
    // [3:0] = 2, [31:16] = device_id
    issueCommand(0x02 | (@as(u64, device_id) << 16), 0);
}

fn invalidateIotlb() void {
    // CMD_INVALIDATE_IOMMU_PAGES (type 0x03)
    // First qword: [3:0]=opcode(3), [20]=S(size=1 → all pages), [47:32]=DomainId
    // With S=1 and DomainId=0: invalidate all pages for all domains
    issueCommand(0x03 | (@as(u64, 1) << 20), 0);
}

pub fn flushAll() void {
    if (!initialized) return;
    invalidateIotlb();
}
