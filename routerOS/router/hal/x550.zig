/// x550 NIC driver — parameterized, no globals.
/// Intel X550-T2 10GbE controller. Uses legacy descriptors for compatibility.
const lib = @import("lib");

const e1000 = @import("e1000.zig");
const syscall = lib.syscall;

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

pub fn readReg(mmio_base: u64, offset: u32) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(mmio_base + offset);
    return ptr.*;
}

pub fn writeReg(mmio_base: u64, offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + offset);
    ptr.* = value;
}

// ── MAC address ────────────────────────────────────────────────────────

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

fn pollWithTimeout(mmio_base: u64, reg: u32, mask: u32, expected: u32, max_iters: u32) bool {
    var i: u32 = 0;
    while (i < max_iters) : (i += 1) {
        if ((readReg(mmio_base, reg) & mask) == expected) return true;
        asm volatile ("pause");
    }
    return false;
}

pub fn init(p: InitParams) bool {
    const base = p.mmio_base;

    // 1. Disable interrupts
    writeReg(base, REG_EIMC, 0x7FFFFFFF);
    _ = readReg(base, REG_EICR);

    // Skip software reset for VFIO passthrough — the device was already
    // initialized by host firmware. A reset through VFIO can leave the NVM
    // inaccessible and registers reading as 0. Instead, just disable RX/TX,
    // reconfigure the rings, and re-enable.

    // Disable RX and TX before reconfiguring
    writeReg(base, REG_RXCTRL, readReg(base, REG_RXCTRL) & ~@as(u32, RXCTRL_RXEN));
    writeReg(base, REG_DMATXCTL, readReg(base, REG_DMATXCTL) & ~@as(u32, DMATXCTL_TE));

    // Disable queue 0 RX/TX
    writeReg(base, REG_RXDCTL, readReg(base, REG_RXDCTL) & ~@as(u32, RXDCTL_ENABLE));
    writeReg(base, REG_TXDCTL, readReg(base, REG_TXDCTL) & ~@as(u32, TXDCTL_ENABLE));

    // Brief pause for queues to drain
    var delay: u32 = 0;
    while (delay < 10_000) : (delay += 1) {
        asm volatile ("pause");
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

/// Check for a received packet. Identical to e1000 (descriptor-only).
pub fn rxPoll(
    rx_descs: *[NUM_RX_DESC]RxDesc,
    rx_tail: *u32,
) ?RxResult {
    return e1000.rxPoll(rx_descs, rx_tail);
}

/// Return an RX buffer to the hardware ring.
pub fn rxReturn(mmio_base: u64, rx_tail: u32) void {
    writeReg(mmio_base, REG_RDT, rx_tail);
    _ = readReg(mmio_base, REG_EICR); // Clear pending interrupt status
}

// ── TX ─────────────────────────────────────────────────────────────────

/// Send a packet by pointing a TX descriptor at an arbitrary DMA address.
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

/// Send a packet by copying data into the TX descriptor's pre-assigned buffer.
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

/// Check if a TX descriptor has completed.
pub fn txDone(tx_descs: *[NUM_TX_DESC]TxDesc, idx: u32) bool {
    return e1000.txDone(tx_descs, idx);
}

// ── Interrupt status ───────────────────────────────────────────────────

/// Clear pending interrupt status (read-to-clear).
pub fn clearIrq(mmio_base: u64) void {
    _ = readReg(mmio_base, REG_EICR);
}

// ── Link status ────────────────────────────────────────────────────────

pub fn linkUp(mmio_base: u64) bool {
    return (readReg(mmio_base, REG_LINKS) & LINKS_LINK_UP) != 0;
}
