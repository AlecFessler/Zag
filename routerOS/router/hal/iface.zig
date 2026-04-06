/// Per-interface state for the monolithic NIC+router process.
/// Each Iface owns one NIC and its associated RX/TX rings.
const lib = @import("lib");
const router = @import("router");

const arp = router.protocols.arp;
const dma = @import("dma.zig");
const nic = @import("nic.zig");
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

const CACHE_LINE = 64;
const PENDING_TX_SLOTS = 4;

pub const TxProducer = enum(u1) { service = 0, dataplane = 1 };

/// SPSC ring buffer for pending TX packets.
/// Producer and consumer cursors are on separate cache lines to avoid false sharing.
pub const PendingTxRing = struct {
    // ── Producer cache line ─────────────────────────────────
    tail: u64 align(CACHE_LINE) = 0,
    cached_head: u64 = 0,
    _pad0: [CACHE_LINE - 16]u8 = .{0} ** (CACHE_LINE - 16),

    // ── Consumer cache line ─────────────────────────────────
    head: u64 align(CACHE_LINE) = 0,
    cached_tail: u64 = 0,
    _pad1: [CACHE_LINE - 16]u8 = .{0} ** (CACHE_LINE - 16),

    // ── Data slots ──────────────────────────────────────────
    lens: [PENDING_TX_SLOTS]u16 = .{0} ** PENDING_TX_SLOTS,
    bufs: [PENDING_TX_SLOTS][nic.PACKET_BUF_SIZE]u8 = undefined,

    comptime {
        if (@offsetOf(PendingTxRing, "tail") / CACHE_LINE == @offsetOf(PendingTxRing, "head") / CACHE_LINE)
            @compileError("tail and head must be on different cache lines");
    }

    /// Enqueue a packet (producer side). Returns false if ring is full.
    fn send(self: *PendingTxRing, data: []const u8) bool {
        if (data.len == 0 or data.len > nic.PACKET_BUF_SIZE) return false;

        const tail = @atomicLoad(u64, &self.tail, .monotonic);

        // Fast path: check cached head
        var free = PENDING_TX_SLOTS -% (tail -% self.cached_head);
        if (free == 0) {
            // Slow path: reload remote head
            self.cached_head = @atomicLoad(u64, &self.head, .acquire);
            free = PENDING_TX_SLOTS -% (tail -% self.cached_head);
            if (free == 0) return false;
        }

        const slot: usize = @intCast(tail % PENDING_TX_SLOTS);
        @memcpy(self.bufs[slot][0..data.len], data);
        self.lens[slot] = @intCast(data.len);

        @atomicStore(u64, &self.tail, tail +% 1, .release);
        return true;
    }

    /// Drain all pending packets (consumer side). Calls transmit_fn for each.
    fn drain(self: *PendingTxRing, iface: *Iface) void {
        var head_val = @atomicLoad(u64, &self.head, .monotonic);

        // Fast path: check cached tail
        if (head_val == self.cached_tail) {
            // Slow path: reload remote tail
            self.cached_tail = @atomicLoad(u64, &self.tail, .acquire);
            if (head_val == self.cached_tail) return;
        }

        const tx_off = if (iface.role == .wan) dma.WAN_TX_BUFS_OFF else dma.LAN_TX_BUFS_OFF;
        const tx_bufs_dma = iface.dma_base + tx_off;
        const tx_bufs_virt = iface.dma_region.virt_base + tx_off;

        while (head_val != self.cached_tail) {
            const slot: usize = @intCast(head_val % PENDING_TX_SLOTS);
            const len = self.lens[slot];
            if (nic.txSendCopy(iface.mmio_base, iface.tx_descs, &iface.tx_tail, tx_bufs_dma, tx_bufs_virt, self.bufs[slot][0..len])) {
                iface.stats.tx_packets += 1;
                iface.stats.tx_bytes += len;
            }
            head_val +%= 1;
        }

        @atomicStore(u64, &self.head, head_val, .release);
    }
};

pub const Iface = struct {
    pub const TX_RING_SLOTS = PENDING_TX_SLOTS;

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
    rx_descs: *[nic.NUM_RX_DESC]nic.RxDesc,
    tx_descs: *[nic.NUM_TX_DESC]nic.TxDesc,
    rx_tail: u32,
    tx_tail: u32,

    // RX buffer state tracking for zero-copy
    rx_buf_state: [nic.NUM_RX_DESC]BufState,
    // For tx_pending buffers: which TX desc index on the OTHER iface
    rx_buf_tx_idx: [nic.NUM_RX_DESC]u8,

    // Per-interface tables
    arp_table: [arp.TABLE_SIZE]arp.ArpEntry,
    stats: IfaceStats,

    // Dual SPSC ring buffers for pending TX.
    // Ring 0: service thread → poll thread
    // Ring 1: other poll thread → this poll thread
    // Design follows libz/channel.zig RingHeader pattern.
    pending_tx: [2]PendingTxRing = .{ .{}, .{} },

    // ── RX ──────────────────────────────────────────────────────────────

    /// Poll for a received packet. Returns the buffer index and length.
    /// The buffer is marked sw_owned and NOT returned to hardware.
    pub fn rxPoll(self: *Iface) ?nic.RxResult {
        const result = nic.rxPoll(self.rx_descs, &self.rx_tail) orelse return null;
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
        return target.dma_base + offset + @as(u64, idx) * nic.PACKET_BUF_SIZE;
    }

    /// Return an RX buffer to the hardware ring.
    pub fn rxReturn(self: *Iface, idx: u5) void {
        self.rx_buf_state[idx] = .free;
        nic.rxReturn(self.mmio_base, self.rx_tail);
    }

    // ── TX ──────────────────────────────────────────────────────────────

    /// Send a packet by pointing a TX descriptor at a DMA address.
    /// Used for zero-copy forwarding. Caller must hold tx_mutex or be the
    /// exclusive poll thread.
    pub fn txSendZeroCopy(self: *Iface, dma_addr: u64, len: u16) bool {
        const ok = nic.txSendAddr(
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
    /// Each producer (service thread, other dataplane thread) has its own
    /// SPSC ring, so no CAS is needed.
    pub fn txSendLocal(self: *Iface, data: []const u8, producer: TxProducer) bool {
        return self.pending_tx[@intFromEnum(producer)].send(data);
    }

    /// Drain all pending TX rings. Called by the poll thread each iteration.
    pub fn drainPendingTx(self: *Iface) void {
        self.pending_tx[0].drain(self);
        self.pending_tx[1].drain(self);
    }

    /// Send a packet directly on the TX ring. Must be called from the poll
    /// thread that owns this interface (no cross-thread synchronization).
    /// Unlike txSendLocal, this can be called multiple times per poll iteration.
    /// Spin-waits for the TX descriptor to become available if the NIC is busy.
    pub fn txSendDirect(self: *Iface, data: []const u8) bool {
        if (data.len == 0 or data.len > nic.PACKET_BUF_SIZE) return false;

        // When running without hardware (mmio_base == 0), fall back to pending TX slot
        if (self.mmio_base == 0) return self.txSendLocal(data, .dataplane);

        const tx_off = if (self.role == .wan) dma.WAN_TX_BUFS_OFF else dma.LAN_TX_BUFS_OFF;
        const tx_bufs_dma = self.dma_base + tx_off;
        const tx_bufs_virt = self.dma_region.virt_base + tx_off;

        // Spin-wait for the descriptor to be available (NIC sets DD when done).
        // On a gigabit link a max-size frame takes ~12us, so this is brief.
        const desc = &self.tx_descs[self.tx_tail];
        var spins: u32 = 0;
        while (@as(*volatile u8, &desc.status).* & nic.TX_DESC_STA_DD == 0) {
            spins += 1;
            if (spins > 1_000_000) return false; // safety bail-out
        }

        if (nic.txSendCopy(self.mmio_base, self.tx_descs, &self.tx_tail, tx_bufs_dma, tx_bufs_virt, data)) {
            self.stats.tx_packets += 1;
            self.stats.tx_bytes += data.len;
            return true;
        }
        return false;
    }

    /// Reclaim RX buffers that were lent to the other NIC's TX (zero-copy).
    /// Call this on the SOURCE iface whose RX buffers were used as TX data
    /// on the OTHER iface.
    pub fn reclaimTxPending(self: *Iface, other: *Iface) void {
        for (&self.rx_buf_state, 0..) |*state, i| {
            if (state.* == .tx_pending) {
                const tx_idx = self.rx_buf_tx_idx[i];
                if (nic.txDone(other.tx_descs, tx_idx)) {
                    state.* = .free;
                    nic.rxReturn(self.mmio_base, self.rx_tail);
                }
            }
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    pub fn linkUp(self: *const Iface) bool {
        return nic.linkUp(self.mmio_base);
    }
};
