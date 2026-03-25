/// Shared DMA region layout for dual-NIC zero-copy router.
/// One SHM mapped to both devices via dma_map (IOMMU or physical passthrough).
const lib = @import("lib");

const e1000 = @import("e1000.zig");

const perms = lib.perms;
const syscall = lib.syscall;

const PAGE = syscall.PAGE4K;

// ── Layout constants ────────────────────────────────────────────────────
// All offsets in bytes from the start of the SHM region.

const RX_DESCS_SIZE = @sizeOf(e1000.RxDesc) * e1000.NUM_RX_DESC; // 512
const TX_DESCS_SIZE = @sizeOf(e1000.TxDesc) * e1000.NUM_TX_DESC; // 512
const RX_BUFS_SIZE = e1000.NUM_RX_DESC * e1000.PACKET_BUF_SIZE; // 64KB
pub const LOCAL_TX_COUNT = e1000.NUM_TX_DESC; // must match TX ring size
const LOCAL_TX_SIZE = LOCAL_TX_COUNT * e1000.PACKET_BUF_SIZE; // 64KB

// Page-aligned offsets
pub const WAN_RX_DESCS_OFF: u64 = 0; // page 0
pub const WAN_TX_DESCS_OFF: u64 = 1 * PAGE; // page 1
pub const LAN_RX_DESCS_OFF: u64 = 2 * PAGE; // page 2
pub const LAN_TX_DESCS_OFF: u64 = 3 * PAGE; // page 3
pub const WAN_RX_BUFS_OFF: u64 = 4 * PAGE; // pages 4-19
pub const LAN_RX_BUFS_OFF: u64 = 20 * PAGE; // pages 20-35
pub const WAN_TX_BUFS_OFF: u64 = 36 * PAGE; // pages 36-51 (WAN local TX)
pub const LAN_TX_BUFS_OFF: u64 = 52 * PAGE; // pages 52-67 (LAN local TX)
// Keep LOCAL_TX_BUFS_OFF as alias for WAN (backward compat)
pub const LOCAL_TX_BUFS_OFF = WAN_TX_BUFS_OFF;

pub const TOTAL_PAGES = 68;
pub const TOTAL_SIZE: u64 = TOTAL_PAGES * PAGE;

// ── Result of DMA setup ─────────────────────────────────────────────────

pub const DmaRegion = struct {
    // Virtual base (CPU address)
    virt_base: u64,
    // DMA base per device (IOMMU-translated or physical)
    wan_dma_base: u64,
    lan_dma_base: u64,

    // Convenience: virtual addresses of each section
    pub fn wanRxDescs(self: DmaRegion) *[e1000.NUM_RX_DESC]e1000.RxDesc {
        return @ptrFromInt(self.virt_base + WAN_RX_DESCS_OFF);
    }
    pub fn wanTxDescs(self: DmaRegion) *[e1000.NUM_TX_DESC]e1000.TxDesc {
        return @ptrFromInt(self.virt_base + WAN_TX_DESCS_OFF);
    }
    pub fn lanRxDescs(self: DmaRegion) *[e1000.NUM_RX_DESC]e1000.RxDesc {
        return @ptrFromInt(self.virt_base + LAN_RX_DESCS_OFF);
    }
    pub fn lanTxDescs(self: DmaRegion) *[e1000.NUM_TX_DESC]e1000.TxDesc {
        return @ptrFromInt(self.virt_base + LAN_TX_DESCS_OFF);
    }

    pub fn wanRxBufVirt(self: DmaRegion, idx: u32) [*]u8 {
        return @ptrFromInt(self.virt_base + WAN_RX_BUFS_OFF + @as(u64, idx) * e1000.PACKET_BUF_SIZE);
    }
    pub fn lanRxBufVirt(self: DmaRegion, idx: u32) [*]u8 {
        return @ptrFromInt(self.virt_base + LAN_RX_BUFS_OFF + @as(u64, idx) * e1000.PACKET_BUF_SIZE);
    }
    pub fn localTxBufVirt(self: DmaRegion, idx: u32) [*]u8 {
        return @ptrFromInt(self.virt_base + LOCAL_TX_BUFS_OFF + @as(u64, idx) * e1000.PACKET_BUF_SIZE);
    }

    // DMA addresses for WAN device
    pub fn wanDma(self: DmaRegion, offset: u64) u64 {
        return self.wan_dma_base + offset;
    }
    // DMA addresses for LAN device
    pub fn lanDma(self: DmaRegion, offset: u64) u64 {
        return self.lan_dma_base + offset;
    }
};

// ── Setup ───────────────────────────────────────────────────────────────

pub fn setup(wan_device_handle: u64, lan_device_handle: u64) ?DmaRegion {
    // Create SHM
    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true, .grant = true }).bits();
    const shm_handle = syscall.shm_create_with_rights(TOTAL_SIZE, shm_rights);
    if (shm_handle <= 0) {
        syscall.write("dma: shm_create failed\n");
        return null;
    }

    // Map into our address space
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();
    const vm = syscall.vm_reserve(0, TOTAL_SIZE, vm_rights);
    if (vm.val < 0) {
        syscall.write("dma: vm_reserve failed\n");
        return null;
    }
    if (syscall.shm_map(@intCast(shm_handle), @intCast(vm.val), 0) != 0) {
        syscall.write("dma: shm_map failed\n");
        return null;
    }

    const virt_base = vm.val2;

    // Zero the entire region
    const ptr: [*]u8 = @ptrFromInt(virt_base);
    @memset(ptr[0..TOTAL_SIZE], 0);

    // DMA-map to both devices (works with or without IOMMU)
    const wan_dma_result = syscall.dma_map(wan_device_handle, @intCast(shm_handle));
    if (wan_dma_result < 0) {
        syscall.write("dma: WAN dma_map failed\n");
        return null;
    }
    const wan_dma_base: u64 = @bitCast(wan_dma_result);

    const lan_dma_result = syscall.dma_map(lan_device_handle, @intCast(shm_handle));
    const lan_dma_base: u64 = if (lan_dma_result >= 0)
        @bitCast(lan_dma_result)
    else
        wan_dma_base;

    return .{
        .virt_base = virt_base,
        .wan_dma_base = wan_dma_base,
        .lan_dma_base = lan_dma_base,
    };
}

/// Setup for single-NIC configuration (WAN only, no LAN).
pub fn setupSingle(wan_device_handle: u64) ?DmaRegion {
    return setupWan(wan_device_handle, null);
}

/// Setup WAN DMA, optionally also mapping LAN device.
pub fn setupWan(wan_device_handle: u64, lan_device_handle: ?u64) ?DmaRegion {
    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true, .grant = true }).bits();
    const shm_handle = syscall.shm_create_with_rights(TOTAL_SIZE, shm_rights);
    if (shm_handle <= 0) return null;

    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();
    const vm = syscall.vm_reserve(0, TOTAL_SIZE, vm_rights);
    if (vm.val < 0) return null;
    if (syscall.shm_map(@intCast(shm_handle), @intCast(vm.val), 0) != 0) return null;

    const virt_base = vm.val2;
    const ptr: [*]u8 = @ptrFromInt(virt_base);
    @memset(ptr[0..TOTAL_SIZE], 0);

    const wan_dma_result = syscall.dma_map(wan_device_handle, @intCast(shm_handle));
    if (wan_dma_result < 0) {
        syscall.write("dma: dma_map failed\n");
        return null;
    }
    const wan_dma_base: u64 = @bitCast(wan_dma_result);

    var lan_dma_base: u64 = 0;
    if (lan_device_handle) |lan_handle| {
        const lan_dma_result = syscall.dma_map(lan_handle, @intCast(shm_handle));
        if (lan_dma_result >= 0) {
            lan_dma_base = @bitCast(lan_dma_result);
        } else {
            syscall.write("dma: LAN dma_map failed\n");
            // WAN-only mode, lan_dma_base stays 0
        }
    }

    return .{
        .virt_base = virt_base,
        .wan_dma_base = wan_dma_base,
        .lan_dma_base = lan_dma_base,
    };
}
