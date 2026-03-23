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

const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
const GSTS_TES: u32 = 1 << 31;
const GSTS_RTPS: u32 = 1 << 30;

const REG_VER = 0x00;
const REG_GCMD = 0x18;
const REG_GSTS = 0x1C;
const REG_RTADDR = 0x20;
const REG_CCMD = 0x28;
const REG_FSTS = 0x34;
const REG_FECTL = 0x38;
const REG_IOTLB = 0x100;

const RootEntry = packed struct(u128) {
    present: bool,
    _res0: u11 = 0,
    context_table_ptr: u52,
    _res1: u64 = 0,
};

const ContextEntry = packed struct(u128) {
    present: bool,
    fault_disable: bool,
    translation_type: u2,
    _res0: u8 = 0,
    slptptr: u52,
    address_width: u3,
    _ignored: u1 = 0,
    _avail: u3 = 0,
    _res1: u1 = 0,
    domain_id: u16,
    _res2: u40 = 0,
};

var iommu_base: u64 = 0;
var root_table_phys: PAddr = PAddr.fromInt(0);
var root_table_virt: VAddr = VAddr.fromInt(0);
var initialized: bool = false;

fn readReg32(offset: u32) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(iommu_base + offset);
    return ptr.*;
}

fn writeReg32(offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(iommu_base + offset);
    ptr.* = value;
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
    const reg_base_virt = VAddr.fromPAddr(reg_base_phys, null);

    try arch.mapPage(memory_init.kernel_addr_space_root, reg_base_phys, reg_base_virt, MMIO_PERMS);
    iommu_base = reg_base_virt.addr;

    const root = try allocZeroedPage();
    root_table_phys = root.phys;
    root_table_virt = root.virt;

    writeReg64(REG_RTADDR, root_table_phys.addr);

    writeReg32(REG_GCMD, readReg32(REG_GCMD) | GCMD_SRTP);
    var timeout: u32 = 0;
    while (timeout < 1000000) : (timeout += 1) {
        if (readReg32(REG_GSTS) & GSTS_RTPS != 0) break;
    }

    writeReg32(REG_GCMD, readReg32(REG_GCMD) | GCMD_TE);
    timeout = 0;
    while (timeout < 1000000) : (timeout += 1) {
        if (readReg32(REG_GSTS) & GSTS_TES != 0) break;
    }

    initialized = true;
}

pub fn setupDevice(device: *DeviceRegion) !void {
    if (!initialized) return;

    const root_entries: *[256]RootEntry = @ptrFromInt(root_table_virt.addr);
    const bus = device.pci_bus;

    if (!root_entries[bus].present) {
        const ctx = try allocZeroedPage();
        root_entries[bus] = .{
            .present = true,
            .context_table_ptr = @truncate(ctx.phys.addr >> 12),
        };
    }

    const ctx_phys = PAddr.fromInt(@as(u64, root_entries[bus].context_table_ptr) << 12);
    const ctx_virt = VAddr.fromPAddr(ctx_phys, null);
    const ctx_entries: *[256]ContextEntry = @ptrFromInt(ctx_virt.addr);
    const ctx_idx = @as(u8, device.pci_dev) * 8 + device.pci_func;

    if (!ctx_entries[ctx_idx].present) {
        const pt = try allocZeroedPage();
        device.dma_page_table_root = pt.phys;
        ctx_entries[ctx_idx] = .{
            .present = true,
            .fault_disable = false,
            .translation_type = 0,
            .address_width = 2,
            .slptptr = @truncate(pt.phys.addr >> 12),
            .domain_id = @as(u16, device.pci_bus) << 8 | @as(u16, ctx_idx),
        };
    }
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
    writeReg64(REG_IOTLB + 8, @as(u64, 1) << 63 | @as(u64, 1) << 60);
    var timeout: u32 = 0;
    while (timeout < 1000000) : (timeout += 1) {
        const val = @as(*const volatile u64, @ptrFromInt(iommu_base + REG_IOTLB + 8)).*;
        if (val & (@as(u64, 1) << 63) == 0) break;
    }
}

pub fn isInitialized() bool {
    return initialized;
}
