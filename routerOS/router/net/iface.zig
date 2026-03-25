/// Per-interface state for the monolithic NIC+router process.
/// Each Iface owns one e1000 NIC and its associated RX/TX rings.
const lib = @import("lib");
const router = @import("router");

const arp = @import("arp.zig");
const dma = @import("dma.zig");
const e1000 = @import("e1000.zig");
const util = router.util;

const syscall = lib.syscall;

pub const Role = enum { wan, lan };

pub const BufState = enum(u8) {
    /// Buffer is in the hardware RX ring, owned by NIC
    free = 0,
    /// Buffer has been received, owned by software
    sw_owned = 1,
    /// Buffer is being used by the other NIC's TX (zero-copy)
    tx_pending = 2,
};

pub const IfaceStats = struct {
    rx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_packets: u64 = 0,
    tx_bytes: u64 = 0,
    rx_dropped: u64 = 0,
};

pub const Iface = struct {
    role: Role,
    mmio_base: u64,
    mac: [6]u8,
    ip: [4]u8,
    ip6_link_local: [16]u8 = .{0} ** 16,
    ip6_global: [16]u8 = .{0} ** 16,
    ip6_global_valid: bool = false,

    // DMA base for this device (IOMMU-translated)
    dma_base: u64,
    // Virtual base of the shared DMA region
    dma_region: *dma.DmaRegion,

    // Descriptor rings (virtual addresses)
    rx_descs: *[e1000.NUM_RX_DESC]e1000.RxDesc,
    tx_descs: *[e1000.NUM_TX_DESC]e1000.TxDesc,
    rx_tail: u32,
    tx_tail: u32,

    // RX buffer state tracking for zero-copy
    rx_buf_state: [e1000.NUM_RX_DESC]BufState,
    // For tx_pending buffers: which TX desc index on the OTHER iface
    rx_buf_tx_idx: [e1000.NUM_RX_DESC]u8,

    // Per-interface tables
    arp_table: [arp.TABLE_SIZE]arp.ArpEntry,
    stats: IfaceStats,

    // Lock-free pending TX: main thread writes packet here, poll thread drains.
    // Atomic flag: 0 = empty, 1 = packet ready.
    pending_tx_flag: u64 align(8) = 0,
    pending_tx_len: u16 = 0,
    pending_tx_buf: [e1000.PACKET_BUF_SIZE]u8 = undefined,

    // ── Initialization ──────────────────────────────────────────────────

    pub fn initWan(region: *dma.DmaRegion) Iface {
        return .{
            .role = .wan,
            .mmio_base = 0,
            .mac = .{ 0, 0, 0, 0, 0, 0 },
            .ip = .{ 10, 0, 2, 15 },
            .dma_base = region.wan_dma_base,
            .dma_region = region,
            .rx_descs = region.wanRxDescs(),
            .tx_descs = region.wanTxDescs(),
            .rx_tail = e1000.NUM_RX_DESC - 1,
            .tx_tail = 0,
            .rx_buf_state = .{.free} ** e1000.NUM_RX_DESC,
            .rx_buf_tx_idx = .{0} ** e1000.NUM_RX_DESC,
            .arp_table = .{arp.empty} ** arp.TABLE_SIZE,
            .stats = .{},
            .pending_tx_flag = 0,
        };
    }

    pub fn initLan(region: *dma.DmaRegion) Iface {
        return .{
            .role = .lan,
            .mmio_base = 0,
            .mac = .{ 0, 0, 0, 0, 0, 0 },
            .ip = .{ 10, 1, 1, 1 },
            .dma_base = region.lan_dma_base,
            .dma_region = region,
            .rx_descs = region.lanRxDescs(),
            .tx_descs = region.lanTxDescs(),
            .rx_tail = e1000.NUM_RX_DESC - 1,
            .tx_tail = 0,
            .rx_buf_state = .{.free} ** e1000.NUM_RX_DESC,
            .rx_buf_tx_idx = .{0} ** e1000.NUM_RX_DESC,
            .arp_table = .{arp.empty} ** arp.TABLE_SIZE,
            .stats = .{},
            .pending_tx_flag = 0,
        };
    }

    // ── RX ──────────────────────────────────────────────────────────────

    /// Poll for a received packet. Returns the buffer index and length.
    /// The buffer is marked sw_owned and NOT returned to hardware.
    pub fn rxPoll(self: *Iface) ?e1000.RxResult {
        const result = e1000.rxPoll(self.rx_descs, &self.rx_tail) orelse return null;
        self.rx_buf_state[result.index] = .sw_owned;
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += result.len;
        return result;
    }

    /// Get a pointer to the RX buffer data for a given index.
    pub fn rxBufPtr(self: *Iface, idx: u5) [*]u8 {
        if (self.role == .wan) {
            return self.dma_region.wanRxBufVirt(idx);
        } else {
            return self.dma_region.lanRxBufVirt(idx);
        }
    }

    /// Get the DMA address of an RX buffer (for zero-copy TX on the OTHER device).
    pub fn rxBufDmaForDevice(self: *Iface, idx: u5, target: *Iface) u64 {
        const offset = if (self.role == .wan) dma.WAN_RX_BUFS_OFF else dma.LAN_RX_BUFS_OFF;
        return target.dma_base + offset + @as(u64, idx) * e1000.PACKET_BUF_SIZE;
    }

    /// Return an RX buffer to the hardware ring.
    pub fn rxReturn(self: *Iface, idx: u5) void {
        self.rx_buf_state[idx] = .free;
        e1000.rxReturn(self.mmio_base, self.rx_tail);
    }

    // ── TX ──────────────────────────────────────────────────────────────

    /// Send a packet by pointing a TX descriptor at a DMA address.
    /// Used for zero-copy forwarding. Caller must hold tx_mutex or be the
    /// exclusive poll thread.
    pub fn txSendZeroCopy(self: *Iface, dma_addr: u64, len: u16) bool {
        const ok = e1000.txSendAddr(
            self.mmio_base,
            self.tx_descs,
            &self.tx_tail,
            dma_addr,
            len,
        );
        if (ok) {
            self.stats.tx_packets += 1;
            self.stats.tx_bytes += len;
        }
        return ok;
    }

    /// Enqueue a locally-generated packet for the poll thread to send.
    /// Lock-free: writes to pending slot, poll thread drains it.
    /// Safe to call from any thread. Returns false if the slot is full.
    pub fn txSendLocal(self: *Iface, data: []const u8) bool {
        if (data.len == 0 or data.len > e1000.PACKET_BUF_SIZE) return false;
        // Check if slot is free
        if (@atomicLoad(u64, &self.pending_tx_flag, .acquire) != 0) return false;
        // Write data and length, then set flag
        @memcpy(self.pending_tx_buf[0..data.len], data);
        self.pending_tx_len = @intCast(data.len);
        @atomicStore(u64, &self.pending_tx_flag, 1, .release);
        return true;
    }

    /// Drain the pending TX slot. Called by the poll thread each iteration.
    pub fn drainPendingTx(self: *Iface) void {
        if (@atomicLoad(u64, &self.pending_tx_flag, .acquire) == 0) return;
        const len = self.pending_tx_len;
        const tx_off = if (self.role == .wan) dma.WAN_TX_BUFS_OFF else dma.LAN_TX_BUFS_OFF;
        const tx_bufs_dma = self.dma_base + tx_off;
        const tx_bufs_virt = self.dma_region.virt_base + tx_off;
        if (e1000.txSendCopy(self.mmio_base, self.tx_descs, &self.tx_tail, tx_bufs_dma, tx_bufs_virt, self.pending_tx_buf[0..len])) {
            self.stats.tx_packets += 1;
            self.stats.tx_bytes += len;
        }
        @atomicStore(u64, &self.pending_tx_flag, 0, .release);
    }

    /// Reclaim RX buffers that were lent to the other NIC's TX (zero-copy).
    /// Call this on the SOURCE iface whose RX buffers were used as TX data
    /// on the OTHER iface.
    pub fn reclaimTxPending(self: *Iface, other: *Iface) void {
        for (&self.rx_buf_state, 0..) |*state, i| {
            if (state.* == .tx_pending) {
                const tx_idx = self.rx_buf_tx_idx[i];
                if (e1000.txDone(other.tx_descs, tx_idx)) {
                    state.* = .free;
                    e1000.rxReturn(self.mmio_base, self.rx_tail);
                }
            }
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    pub fn linkUp(self: *const Iface) bool {
        return (e1000.readReg(self.mmio_base, e1000.REG_STATUS) & 0x02) != 0;
    }
};
