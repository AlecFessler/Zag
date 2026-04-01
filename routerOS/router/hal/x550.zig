/// x550 NIC driver — parameterized, no globals.
/// Intel X550-T2 10GbE controller. Uses legacy descriptors for compatibility.
const build_options = @import("build_options");

const e1000 = @import("e1000.zig");

// ── Re-export shared types (legacy descriptors are identical) ──────────
pub const RxDesc = e1000.RxDesc;
pub const TxDesc = e1000.TxDesc;
pub const RxResult = e1000.RxResult;
pub const InitParams = e1000.InitParams;
pub const NUM_RX_DESC = e1000.NUM_RX_DESC;
pub const NUM_TX_DESC = e1000.NUM_TX_DESC;
pub const PACKET_BUF_SIZE = e1000.PACKET_BUF_SIZE;
pub const RX_DESC_DD = e1000.RX_DESC_DD;
pub const TX_DESC_CMD_EOP = e1000.TX_DESC_CMD_EOP;
pub const TX_DESC_CMD_IFCS = e1000.TX_DESC_CMD_IFCS;
pub const TX_DESC_CMD_RS = e1000.TX_DESC_CMD_RS;
pub const TX_DESC_STA_DD = e1000.TX_DESC_STA_DD;

// ── Register offsets ───────────────────────────────────────────────────
pub const REG_CTRL = 0x00000000;
pub const REG_STATUS = 0x00000008;
pub const REG_CTRL_EXT = 0x00000018;
pub const REG_EICR = 0x00000800;
pub const REG_EIMS = 0x00000880;
pub const REG_EIMC = 0x00000888;
pub const REG_RXCTRL = 0x00003000;
pub const REG_DMATXCTL = 0x00004A80;
pub const REG_HLREG0 = 0x00004240;
pub const REG_LINKS = 0x000042A4;
pub const REG_FCTRL = 0x00005080;
pub const REG_EEC = 0x00010010;
pub const REG_EEMNGCTL = 0x00010110;
pub const REG_RDRXCTL = 0x00002F00;

// Per-queue RX registers (queue 0)
pub const REG_RDBAL = 0x00001000;
pub const REG_RDBAH = 0x00001004;
pub const REG_RDLEN = 0x00001008;
pub const REG_RDH = 0x00001010;
pub const REG_SRRCTL = 0x00001014;
pub const REG_RDT = 0x00001018;
pub const REG_RXDCTL = 0x00001028;

// Per-queue TX registers (queue 0)
pub const REG_TDBAL = 0x00006000;
pub const REG_TDBAH = 0x00006004;
pub const REG_TDLEN = 0x00006008;
pub const REG_TDH = 0x00006010;
pub const REG_TDT = 0x00006018;
pub const REG_TXDCTL = 0x00006028;

// MAC address (primary, also aliased at 0x5400/0x5404)
pub const REG_RAL = 0x0000A200;
pub const REG_RAH = 0x0000A204;

pub const REG_MTA = 0x00005200;

// ── Control register bits ──────────────────────────────────────────────
const CTRL_RST = 1 << 26;
const CTRL_LRST = 1 << 3;

const EEC_AUTO_RD = 1 << 9;
const EEMNGCTL_CFG_DONE0 = 1 << 18;
const RDRXCTL_DMAIDONE = 1 << 3;

const FCTRL_BAM = 1 << 10;

const RXDCTL_ENABLE = 1 << 25;
const RXCTRL_RXEN = 1 << 0;

const HLREG0_TXPADEN = 1 << 10;
const HLREG0_TXSA = 1 << 5;

const TXDCTL_ENABLE = 1 << 25;
const DMATXCTL_TE = 1 << 0;

const LINKS_LINK_UP = 1 << 30;

// ── MMIO helpers ───────────────────────────────────────────────────────

/// Reads a 32-bit MMIO register at mmio_base + offset
/// (X550 Datasheet §8.1.1 Memory-Mapped Access).
///
/// All X550 internal registers are accessed as 32-bit memory-mapped I/O.
/// The volatile pointer ensures the compiler does not elide or reorder
/// the load, which is critical for hardware register reads where the
/// value may change between accesses (e.g. status registers, read-to-clear
/// registers like EICR at 0x00000800).
pub fn readReg(mmio_base: u64, offset: u32) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(mmio_base + offset);
    return ptr.*;
}

/// Writes a 32-bit value to an MMIO register at mmio_base + offset
/// (X550 Datasheet §8.1.1 Memory-Mapped Access).
///
/// The volatile pointer ensures the compiler emits the store at exactly
/// this point in the instruction stream. Ordering matters for hardware
/// registers — e.g. EIMC must be written before EICR is read during
/// interrupt disable sequences (§4.6.3.1).
pub fn writeReg(mmio_base: u64, offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + offset);
    ptr.* = value;
}

// ── MAC address ────────────────────────────────────────────────────────

/// Reads the 6-byte Ethernet MAC address from the Receive Address registers
/// RAL[0] (0x0000A200, §8.2.2.8.14) and RAH[0] (0x0000A204, §8.2.2.8.15).
///
/// RAL[31:0] contains the lower 4 bytes of the 48-bit MAC address in
/// big-endian wire order (LS byte of RAL is first on the wire).
/// RAH[15:0] contains the upper 2 bytes. RAL[0] is automatically loaded
/// from NVM on reset if the NVM is present (§8.2.2.8.14). The first 16
/// MAC addresses are also aliased at 0x5400-0x5478 for backward
/// compatibility (§8.2.2.8.10).
pub fn readMac(mmio_base: u64) [6]u8 {
    const ral = readReg(mmio_base, REG_RAL);
    const rah = readReg(mmio_base, REG_RAH);
    return .{
        @truncate(ral),
        @truncate(ral >> 8),
        @truncate(ral >> 16),
        @truncate(ral >> 24),
        @truncate(rah),
        @truncate(rah >> 8),
    };
}

// ── Device init ────────────────────────────────────────────────────────

/// Polls an MMIO register until (reg & mask) == expected, or max_iters is exceeded.
///
/// Used throughout the initialization sequence (§4.6.3) to wait for
/// self-clearing bits and status indications:
///   - CTRL.RST[26] self-clears after software reset (§8.2.2.1.1)
///   - EEC.AUTO_RD[9] signals NVM auto-read completion (§8.2.2.2.1)
///   - EEMNGCTL.CFG_DONE0[18] signals manageability config done (§8.2.2.2.3)
///   - RDRXCTL.DMAIDONE[3] signals DMA initialization done (§8.2.2.9.10)
///   - RXDCTL.ENABLE[25] / TXDCTL.ENABLE[25] confirm queue enable (§8.2.2.9.7, §8.2.2.10.10)
///
/// The `pause` instruction hints the CPU to reduce power and avoid
/// memory-order violations during the spin loop.
fn pollWithTimeout(mmio_base: u64, reg: u32, mask: u32, expected: u32, max_iters: u32) bool {
    var i: u32 = 0;
    while (i < max_iters) : (i += 1) {
        if ((readReg(mmio_base, reg) & mask) == expected) return true;
        asm volatile ("pause");
    }
    return false;
}

/// Initializes the X550-T2 10GbE controller for normal operation
/// (X550 Datasheet §4.6.3 Initialization Sequence).
///
/// Implements the datasheet's prescribed init flow, which varies depending
/// on whether the device is accessed via VFIO passthrough or bare metal:
///
/// **Common preamble (both paths):**
///   1. Disable interrupts — write 0x7FFFFFFF to EIMC (0x00000888, §8.2.2.6.6)
///      to mask all interrupt causes, then read EICR (0x00000800, §8.2.2.6.1)
///      to clear any pending status (§4.6.3.1).
///
/// **VFIO passthrough path** (build_options.passthrough == true):
///   The host firmware already initialized the device. A full reset through
///   VFIO can leave the NVM inaccessible and registers reading as zero. Instead,
///   disable the RX/TX paths to safely reconfigure descriptor rings:
///     - Clear RXCTRL.RXEN[0] (§8.2.2.9.11) — disable global receive
///     - Clear DMATXCTL.TE[0] (§8.2.2.10.2) — disable global transmit
///     - Clear RXDCTL[0].ENABLE[25] (§8.2.2.9.7) — disable RX queue 0
///     - Clear TXDCTL[0].ENABLE[25] (§8.2.2.10.10) — disable TX queue 0
///     - Brief delay for pending DMA to drain
///
/// **Bare metal path** per §4.6.3.2 (Global Reset and General Configuration):
///   2. Software reset — set CTRL.RST[26] (§8.2.2.1.1), which performs a
///      complete device reset (software reset + link reset = global reset).
///      This bit is self-clearing; poll until it reads 0. Then wait ≥10ms
///      for the device to stabilize (§4.6.3.2: "wait at least 10 ms").
///   3. Disable interrupts again after reset (§4.6.3.1).
///   4. Wait for NVM auto-read — poll EEC.AUTO_RD[9] (§8.2.2.2.1).
///      Set when hardware finishes reading NVM after reset.
///   5. Wait for manageability config done — poll EEMNGCTL.CFG_DONE0[18]
///      (§8.2.2.2.3). Non-fatal on x550-T2 (no BMC present).
///   6. Wait for DMA initialization done — poll RDRXCTL.DMAIDONE[3]
///      (§8.2.2.9.10). Required before configuring DMA resources.
///
/// **Common tail (both paths):**
///   7. Clear Multicast Table Array — MTA[0..127] at 0x00005200 (§8.2.2.8.9),
///      128 entries × 4 bytes covering 4096 hash bits.
///   8. Enable broadcast — set FCTRL.BAM[10] (§8.2.2.8.4) to accept
///      broadcast packets to host.
///
/// **RX ring setup** per §4.6.7.1 (Receive Queues Enable):
///   - Initialize legacy RX descriptors (§7.1.5.1, Table 7-15) with
///     buffer physical addresses, zero status fields.
///   - Program descriptor ring base: RDBAL (0x00001000), RDBAH (0x00001004).
///   - Program ring length: RDLEN (0x00001008) = sizeof(RxDesc) * NUM_RX_DESC.
///   - Zero head pointer: RDH (0x00001010).
///   - Configure SRRCTL[0] (0x00001014, §8.2.2.9.5):
///     BSIZEPACKET[4:0] = 0x02 (2 KB buffers), DESCTYPE[27:25] = 000 (legacy).
///   - Enable RX queue: set RXDCTL[0].ENABLE[25] (§8.2.2.9.7), poll until
///     the bit reads back as 1 confirming the queue is active (§4.6.7.1 step 9-10).
///   - Set RDT (0x00001018) to NUM_RX_DESC-1 to make all descriptors available.
///     Per §4.6.7.1 step 10: "The tail should not be bumped before [ENABLE] was
///     read as 1b."
///   - Enable global receive: set RXCTRL.RXEN[0] (§8.2.2.9.11).
///
/// **TX ring setup** per §4.6.8 / §4.6.8.1 (Transmit Queues Enable):
///   - Initialize legacy TX descriptors (§7.2.3.2.2, Table 7-33) with
///     buffer addresses, status = DD (marking them as available).
///   - Program descriptor ring base: TDBAL (0x00006000), TDBAH (0x00006004).
///   - Program ring length: TDLEN (0x00006008), head TDH (0x00006010),
///     tail TDT (0x00006018) both to zero.
///   - Configure HLREG0 (0x00004240, §8.2.2.16.1): clear bit 5 (TXSA —
///     Tx Source Address insertion, identified by the Linux ixgbe driver;
///     datasheet marks bits[9:3] as reserved/must-be-0x7F). Set
///     TXPADEN[10] to pad short frames to 64 bytes.
///   - Enable global transmit: set DMATXCTL.TE[0] (§8.2.2.10.2).
///     Per §4.6.8.1 note: "Queue 0 is enabled by default when DMATXCTL.TE
///     is set."
///   - Enable TX queue: set TXDCTL[0].ENABLE[25] (§8.2.2.10.10), poll
///     until the bit reads back as 1 (§4.6.8.1 step 6).
pub fn init(p: InitParams) bool {
    const base = p.mmio_base;

    // 1. Disable interrupts
    writeReg(base, REG_EIMC, 0x7FFFFFFF);
    _ = readReg(base, REG_EICR);

    if (build_options.passthrough) {
        // VFIO passthrough: device was already initialized by host firmware.
        // A reset through VFIO can leave the NVM inaccessible and registers
        // reading as 0. Just disable RX/TX, reconfigure rings, and re-enable.
        writeReg(base, REG_RXCTRL, readReg(base, REG_RXCTRL) & ~@as(u32, RXCTRL_RXEN));
        writeReg(base, REG_DMATXCTL, readReg(base, REG_DMATXCTL) & ~@as(u32, DMATXCTL_TE));
        writeReg(base, REG_RXDCTL, readReg(base, REG_RXDCTL) & ~@as(u32, RXDCTL_ENABLE));
        writeReg(base, REG_TXDCTL, readReg(base, REG_TXDCTL) & ~@as(u32, TXDCTL_ENABLE));
        var delay: u32 = 0;
        while (delay < 10_000) : (delay += 1) {
            asm volatile ("pause");
        }
    } else {
        // Bare metal: full init per datasheet Section 4.6.3.
        // 2. Software reset (global reset = software reset + link reset)
        writeReg(base, REG_CTRL, readReg(base, REG_CTRL) | CTRL_RST);
        if (!pollWithTimeout(base, REG_CTRL, CTRL_RST, 0, 1_000_000)) {
            return false;
        }

        // Wait at least 10ms after reset (datasheet 4.6.3.2)
        var d: u32 = 0;
        while (d < 10_000_000) : (d += 1) {
            asm volatile ("pause");
        }

        // 3. Disable interrupts again after reset
        writeReg(base, REG_EIMC, 0x7FFFFFFF);
        _ = readReg(base, REG_EICR);

        // 4. Wait for NVM auto-read completion
        if (!pollWithTimeout(base, REG_EEC, EEC_AUTO_RD, EEC_AUTO_RD, 1_000_000)) {
            return false;
        }

        // 5. Wait for manageability configuration done (non-fatal — x550-T2 has no BMC)
        _ = pollWithTimeout(base, REG_EEMNGCTL, EEMNGCTL_CFG_DONE0, EEMNGCTL_CFG_DONE0, 1_000_000);

        // 6. Wait for DMA initialization done
        if (!pollWithTimeout(base, REG_RDRXCTL, RDRXCTL_DMAIDONE, RDRXCTL_DMAIDONE, 1_000_000)) {
            return false;
        }
    }

    // 7. Clear multicast table
    var i: u32 = 0;
    while (i < 128) : (i += 1) {
        writeReg(base, REG_MTA + i * 4, 0);
    }

    // 8. Set broadcast accept mode
    writeReg(base, REG_FCTRL, readReg(base, REG_FCTRL) | FCTRL_BAM);

    // ── RX ring setup (queue 0) ────────────────────────────────────────

    i = 0;
    while (i < NUM_RX_DESC) : (i += 1) {
        p.rx_descs[i].buffer_addr = p.rx_bufs_dma_base + @as(u64, i) * PACKET_BUF_SIZE;
        p.rx_descs[i].status = 0;
    }

    writeReg(base, REG_RDBAL, @truncate(p.rx_descs_dma));
    writeReg(base, REG_RDBAH, @truncate(p.rx_descs_dma >> 32));
    writeReg(base, REG_RDLEN, @sizeOf(RxDesc) * NUM_RX_DESC);
    writeReg(base, REG_RDH, 0);

    // SRRCTL: legacy descriptor type (000), packet buffer size = 2 KB
    writeReg(base, REG_SRRCTL, 0x02); // BSIZEPACKET=2 (2KB), DESCTYPE=000 (legacy)

    // Enable RX queue, poll until enabled
    writeReg(base, REG_RXDCTL, readReg(base, REG_RXDCTL) | RXDCTL_ENABLE);
    _ = pollWithTimeout(base, REG_RXDCTL, RXDCTL_ENABLE, RXDCTL_ENABLE, 1_000_000);

    // Set RDT after queue is enabled
    writeReg(base, REG_RDT, NUM_RX_DESC - 1);

    // Enable global RX
    writeReg(base, REG_RXCTRL, readReg(base, REG_RXCTRL) | RXCTRL_RXEN);

    // ── TX ring setup (queue 0) ────────────────────────────────────────

    i = 0;
    while (i < NUM_TX_DESC) : (i += 1) {
        p.tx_descs[i].buffer_addr = p.tx_bufs_dma_base + @as(u64, i) * PACKET_BUF_SIZE;
        p.tx_descs[i].status = TX_DESC_STA_DD;
    }

    writeReg(base, REG_TDBAL, @truncate(p.tx_descs_dma));
    writeReg(base, REG_TDBAH, @truncate(p.tx_descs_dma >> 32));
    writeReg(base, REG_TDLEN, @sizeOf(TxDesc) * NUM_TX_DESC);
    writeReg(base, REG_TDH, 0);
    writeReg(base, REG_TDT, 0);

    // HLREG0: clear source address insertion (bit 5), enable TX padding (bit 10)
    // TXSA may be left on by the host driver before VFIO took over.
    const hlreg0 = readReg(base, REG_HLREG0);
    writeReg(base, REG_HLREG0, (hlreg0 & ~@as(u32, HLREG0_TXSA)) | HLREG0_TXPADEN);

    // Enable global TX first (datasheet: queue 0 is enabled when DMATXCTL.TE is set)
    writeReg(base, REG_DMATXCTL, readReg(base, REG_DMATXCTL) | DMATXCTL_TE);

    // Enable TX queue
    writeReg(base, REG_TXDCTL, readReg(base, REG_TXDCTL) | TXDCTL_ENABLE);
    _ = pollWithTimeout(base, REG_TXDCTL, TXDCTL_ENABLE, TXDCTL_ENABLE, 1_000_000);

    return true;
}

// ── RX poll ────────────────────────────────────────────────────────────

/// Polls for a received packet by checking the next RX descriptor's DD bit
/// (X550 Datasheet §7.1.5.1 Legacy Receive Descriptor Format, Table 7-15).
///
/// Delegates to e1000.rxPoll — the legacy RX descriptor format is identical
/// between e1000 and X550 (both use the 16-byte layout: 8-byte buffer address,
/// then length[15:0], checksum[15:0], status[7:0], errors[7:0], special[15:0]).
///
/// Hardware sets RDESC.STATUS.DD[0] (Table 7-16) when a packet has been DMA'd
/// into the descriptor's buffer. The status byte is read through a volatile
/// pointer to ensure the compiler does not cache a stale value. Returns the
/// buffer index and packet length, or null if no packet is ready.
///
/// The caller must subsequently call rxReturn() to advance RDT and return
/// the buffer to the hardware ring.
pub fn rxPoll(
    rx_descs: *[NUM_RX_DESC]RxDesc,
    rx_tail: *u32,
) ?RxResult {
    return e1000.rxPoll(rx_descs, rx_tail);
}

/// Returns an RX buffer to the hardware ring by advancing the Receive
/// Descriptor Tail register RDT[0] (0x00001018, §8.2.2.9.6).
///
/// Writing RDT tells the hardware that descriptors up to (but not including)
/// the written index are available for new packets. Per §4.6.7.1 step 11:
/// "Bump the tail pointer (RDT) to enable descriptors fetching."
///
/// Also reads EICR (0x00000800, §8.2.2.6.1) to clear any pending interrupt
/// status. EICR is RW1C and optionally read-to-clear depending on the
/// GPIE.ODC flag (§8.2.2.6.9). This ensures the interrupt line is
/// deasserted so the next packet triggers a fresh interrupt.
pub fn rxReturn(mmio_base: u64, rx_tail: u32) void {
    writeReg(mmio_base, REG_RDT, rx_tail);
    _ = readReg(mmio_base, REG_EICR); // Clear pending interrupt status
}

// ── TX ─────────────────────────────────────────────────────────────────

/// Transmits a packet by pointing a legacy TX descriptor at an arbitrary
/// DMA address — used for zero-copy forwarding where the packet data
/// already resides in a DMA-accessible buffer (e.g. another NIC's RX buffer).
/// (X550 Datasheet §7.2.3.2.2 Legacy Transmit Descriptor Format, Table 7-33).
///
/// First checks TDESC.STA.DD[0] (Table 7-34) via volatile read to confirm
/// the descriptor has been written back by hardware and is available for reuse.
/// Returns false if the descriptor is still in use (TX ring full).
///
/// Sets the command byte (TDESC.CMD, Table 7-35):
///   - EOP[0] = 1 — End of Packet, this is the only descriptor for the frame
///   - IFCS[1] = 1 — Insert FCS, hardware appends the 4-byte Ethernet CRC
///     (required when HLREG0.TXPADEN is set, per §7.2.3.2.2)
///   - RS[3] = 1 — Report Status, hardware sets DD on completion so software
///     can reclaim the descriptor (§7.2.3.5.1: "When TXDCTL.WTHRESH = zero,
///     software must set the RS bit on the last descriptor of every packet")
///
/// Writing TDT (0x00006018) advances the tail pointer, triggering the
/// hardware to fetch and process the new descriptor (§7.2.3.4).
pub fn txSendAddr(
    mmio_base: u64,
    tx_descs: *[NUM_TX_DESC]TxDesc,
    tx_tail: *u32,
    dma_addr: u64,
    len: u16,
) bool {
    const desc = &tx_descs[tx_tail.*];
    if (@as(*volatile u8, &desc.status).* & TX_DESC_STA_DD == 0) return false;

    desc.buffer_addr = dma_addr;
    desc.length = len;
    desc.cmd = TX_DESC_CMD_EOP | TX_DESC_CMD_IFCS | TX_DESC_CMD_RS;
    desc.status = 0;

    tx_tail.* = (tx_tail.* + 1) % NUM_TX_DESC;
    writeReg(mmio_base, REG_TDT, tx_tail.*);
    return true;
}

/// Transmits a packet by copying data into the TX descriptor's pre-assigned
/// DMA buffer — used for locally-generated packets (ARP, DHCP, ICMP replies)
/// where the data originates in non-DMA memory.
/// (X550 Datasheet §7.2.3.2.2 Legacy Transmit Descriptor Format, Table 7-33).
///
/// Same descriptor setup as txSendAddr (DD check, EOP|IFCS|RS command bits,
/// TDT tail bump), but first copies the packet data into the pre-allocated
/// TX buffer at tx_bufs_virt_base + idx * PACKET_BUF_SIZE, then points the
/// descriptor's buffer_addr at the corresponding DMA physical address.
/// Returns false if data is empty, exceeds PACKET_BUF_SIZE, or no
/// descriptor is available.
pub fn txSendCopy(
    mmio_base: u64,
    tx_descs: *[NUM_TX_DESC]TxDesc,
    tx_tail: *u32,
    dma_base: u64,
    tx_bufs_virt_base: u64,
    data: []const u8,
) bool {
    if (data.len == 0 or data.len > PACKET_BUF_SIZE) return false;

    const idx = tx_tail.*;
    const desc = &tx_descs[idx];
    if (@as(*volatile u8, &desc.status).* & TX_DESC_STA_DD == 0) return false;

    const buf_virt = tx_bufs_virt_base + @as(u64, idx) * PACKET_BUF_SIZE;
    const dst: [*]u8 = @ptrFromInt(buf_virt);
    @memcpy(dst[0..data.len], data);

    desc.buffer_addr = dma_base + @as(u64, idx) * PACKET_BUF_SIZE;
    desc.length = @intCast(data.len);
    desc.cmd = TX_DESC_CMD_EOP | TX_DESC_CMD_IFCS | TX_DESC_CMD_RS;
    desc.status = 0;

    tx_tail.* = (tx_tail.* + 1) % NUM_TX_DESC;
    writeReg(mmio_base, REG_TDT, tx_tail.*);
    return true;
}

/// Checks if a TX descriptor has completed DMA by reading TDESC.STA.DD[0]
/// (X550 Datasheet §7.2.3.2.2, Table 7-34 Transmit Descriptor Write-Back).
///
/// Delegates to e1000.txDone — the legacy TX descriptor write-back format
/// is identical. Hardware sets DD when the descriptor's data has been
/// fetched and the descriptor is safe to reuse. Used for zero-copy buffer
/// reclamation: after txSendAddr points a descriptor at another NIC's RX
/// buffer, the caller polls txDone to know when the buffer can be returned
/// to the source NIC's RX ring.
pub fn txDone(tx_descs: *[NUM_TX_DESC]TxDesc, idx: u32) bool {
    return e1000.txDone(tx_descs, idx);
}

// ── Interrupt status ───────────────────────────────────────────────────

/// Clears pending interrupt status by reading the Extended Interrupt Cause
/// Register EICR (0x00000800, §8.2.2.6.1).
///
/// EICR is RW1C (write-1-to-clear) and can optionally auto-clear on read
/// depending on GPIE.ODC (§8.2.2.6.9). The read drains any latched interrupt
/// causes — RTXQ[15:0] for RX/TX queue events, LSC[20] for link status
/// changes, etc. — so the interrupt line is deasserted.
pub fn clearIrq(mmio_base: u64) void {
    _ = readReg(mmio_base, REG_EICR);
}

// ── Link status ────────────────────────────────────────────────────────

/// Returns true if the physical link is up by reading LINKS.LINK_UP[30]
/// (0x000042A4, §8.2.2.16.7 Link Status Register).
///
/// LINK_UP reflects the PHY's internal indication to the MAC:
///   0 = link is down, 1 = link is up.
/// The LINKS register also provides LINK_SPEED[29:28] (00=rsvd, 01=100M,
/// 10=1G, 11=10G) and LINK_STATUS[7] (latching low — cleared on read if
/// the link went down since last read), but this function only checks
/// the instantaneous LINK_UP bit.
pub fn linkUp(mmio_base: u64) bool {
    return (readReg(mmio_base, REG_LINKS) & LINKS_LINK_UP) != 0;
}
