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
    host_page_table_root_lo: u45,
    paging_mode: u3 = 4,
    ir: bool = false,
    iw: bool = false,
    _res1: u6 = 0,
    domain_id: u16,
    _res2: u49 = 0,
    _res3: u128 = 0,
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

fn allocZeroedPages(num: u32) !struct { phys: PAddr, virt: VAddr } {
    const pmm_iface = pmm.global_pmm.?.allocator();
    const first = try pmm_iface.create(paging.PageMem(.page4k));
    @memset(std.mem.asBytes(first), 0);

    var i: u32 = 1;
    while (i < num) : (i += 1) {
        const page = try pmm_iface.create(paging.PageMem(.page4k));
        @memset(std.mem.asBytes(page), 0);
    }

    const virt = VAddr.fromInt(@intFromPtr(first));
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

    const dt_pages: u32 = 8;
    dev_table_size = @as(u64, dt_pages) * paging.PAGE4K;
    const dt = try allocZeroedPage();
    dev_table_phys = dt.phys;
    dev_table_virt = dt.virt;

    const dt_entries = dev_table_size / 32;
    const dt_size_bits: u64 = std.math.log2(dt_entries) - 1;
    writeReg64(MMIO_DEV_TABLE_BASE, dev_table_phys.addr | (dt_size_bits & 0x1FF));

    const cmd = try allocZeroedPage();
    cmd_buf_phys = cmd.phys;
    cmd_buf_virt = cmd.virt;
    const cmd_len_bits: u64 = 8;
    writeReg64(MMIO_CMD_BUF_BASE, cmd_buf_phys.addr | (cmd_len_bits << 56));

    var ctrl = readReg64(MMIO_CONTROL);
    ctrl |= CTRL_IOMMU_EN | CTRL_CMD_BUF_EN;
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

    const entry_ptr: *DeviceTableEntry = @ptrFromInt(dev_table_virt.addr + entry_offset);
    entry_ptr.* = .{
        .valid = true,
        .translation_valid = true,
        .host_page_table_root_lo = @truncate(pt.phys.addr >> 12),
        .domain_id = device_id,
    };
}

pub fn mapDmaPage(device: *DeviceRegion, dma_addr: u64, phys: PAddr) !void {
    if (!initialized or device.dma_page_table_root.addr == 0) return error.NotSetup;

    const pml4_virt = VAddr.fromPAddr(device.dma_page_table_root, null);
    const pml4: *[512]u64 = @ptrFromInt(pml4_virt.addr);

    const pml4_idx: u9 = @truncate((dma_addr >> 39) & 0x1FF);
    const pdpt_idx: u9 = @truncate((dma_addr >> 30) & 0x1FF);
    const pd_idx: u9 = @truncate((dma_addr >> 21) & 0x1FF);
    const pt_idx: u9 = @truncate((dma_addr >> 12) & 0x1FF);

    if (pml4[pml4_idx] & 1 == 0) {
        const page = try allocZeroedPage();
        pml4[pml4_idx] = page.phys.addr | 0x3;
    }
    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0xFFFFFFFFF000), null).addr);

    if (pdpt[pdpt_idx] & 1 == 0) {
        const page = try allocZeroedPage();
        pdpt[pdpt_idx] = page.phys.addr | 0x3;
    }
    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0xFFFFFFFFF000), null).addr);

    if (pd[pd_idx] & 1 == 0) {
        const page = try allocZeroedPage();
        pd[pd_idx] = page.phys.addr | 0x3;
    }
    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & 0xFFFFFFFFF000), null).addr);

    pt[pt_idx] = phys.addr | 0x3;
}

pub fn unmapDmaPage(device: *DeviceRegion, dma_addr: u64) void {
    if (!initialized or device.dma_page_table_root.addr == 0) return;

    const pml4_virt = VAddr.fromPAddr(device.dma_page_table_root, null);
    const pml4: *[512]u64 = @ptrFromInt(pml4_virt.addr);
    const pml4_idx: u9 = @truncate((dma_addr >> 39) & 0x1FF);
    if (pml4[pml4_idx] & 1 == 0) return;

    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0xFFFFFFFFF000), null).addr);
    const pdpt_idx: u9 = @truncate((dma_addr >> 30) & 0x1FF);
    if (pdpt[pdpt_idx] & 1 == 0) return;

    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0xFFFFFFFFF000), null).addr);
    const pd_idx: u9 = @truncate((dma_addr >> 21) & 0x1FF);
    if (pd[pd_idx] & 1 == 0) return;

    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & 0xFFFFFFFFF000), null).addr);
    const pt_idx: u9 = @truncate((dma_addr >> 12) & 0x1FF);
    pt[pt_idx] = 0;

    invalidateIotlb();
}

fn invalidateIotlb() void {
    const tail = readReg64(MMIO_CMD_BUF_TAIL);
    const cmd_ptr: *[2]u64 = @ptrFromInt(cmd_buf_virt.addr + (tail & 0xFFF));
    cmd_ptr[0] = 0x01;
    cmd_ptr[1] = 0;
    writeReg64(MMIO_CMD_BUF_TAIL, (tail + 16) & 0xFFF);
}

pub fn isInitialized() bool {
    return initialized;
}
