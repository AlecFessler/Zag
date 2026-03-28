/// e1000 NIC driver — parameterized, no globals.
/// Extracted from nic_driver/main.zig for the monolithic router process.
const lib = @import("lib");

const syscall = lib.syscall;

// ── Register offsets ────────────────────────────────────────────────────
pub const REG_CTRL = 0x0000;
pub const REG_STATUS = 0x0008;
pub const REG_ICR = 0x00C0;
pub const REG_IMS = 0x00D0;
pub const REG_IMC = 0x00D8;
pub const REG_RCTL = 0x0100;
pub const REG_TCTL = 0x0400;
pub const REG_RDBAL = 0x2800;
pub const REG_RDBAH = 0x2804;
pub const REG_RDLEN = 0x2808;
pub const REG_RDH = 0x2810;
pub const REG_RDT = 0x2818;
pub const REG_TDBAL = 0x3800;
pub const REG_TDBAH = 0x3804;
pub const REG_TDLEN = 0x3808;
pub const REG_TDH = 0x3810;
pub const REG_TDT = 0x3818;
pub const REG_MTA = 0x5200;
pub const REG_RAL = 0x5400;
pub const REG_RAH = 0x5404;

const CTRL_RST = 1 << 26;
const CTRL_SLU = 1 << 6;
const CTRL_ASDE = 1 << 5;

pub const RCTL_EN = 1 << 1;
pub const RCTL_BAM = 1 << 15;
pub const RCTL_SECRC = 1 << 26;

const TCTL_EN = 1 << 1;
const TCTL_PSP = 1 << 3;

pub const RX_DESC_DD = 1 << 0;
pub const TX_DESC_CMD_EOP = 1 << 0;
pub const TX_DESC_CMD_IFCS = 1 << 1;
pub const TX_DESC_CMD_RS = 1 << 3;
pub const TX_DESC_STA_DD = 1 << 0;

pub const NUM_RX_DESC = 32;
pub const NUM_TX_DESC = 32;
pub const PACKET_BUF_SIZE = 2048;

// ── Descriptor types ────────────────────────────────────────────────────

pub const RxDesc = extern struct {
    buffer_addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
};

pub const TxDesc = extern struct {
    buffer_addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
};

// ── MMIO helpers ────────────────────────────────────────────────────────

pub fn readReg(mmio_base: u64, offset: u32) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(mmio_base + offset);
    return ptr.*;
}

pub fn writeReg(mmio_base: u64, offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + offset);
    ptr.* = value;
}

// ── MAC address ─────────────────────────────────────────────────────────

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

// ── Device init ─────────────────────────────────────────────────────────

pub const InitParams = struct {
    mmio_base: u64,
    rx_descs_dma: u64,
    tx_descs_dma: u64,
    rx_bufs_dma_base: u64,
    tx_bufs_dma_base: u64,
    rx_descs: *[NUM_RX_DESC]RxDesc,
    tx_descs: *[NUM_TX_DESC]TxDesc,
};

pub fn init(p: InitParams) bool {
    const base = p.mmio_base;

    // Disable interrupts, clear pending
    writeReg(base, REG_IMC, 0xFFFFFFFF);
    _ = readReg(base, REG_ICR);

    // Reset device
    writeReg(base, REG_CTRL, readReg(base, REG_CTRL) | CTRL_RST);
    var i: u32 = 0;
    while (i < 1000000) : (i += 1) {
        if ((readReg(base, REG_CTRL) & CTRL_RST) == 0) break;
    }
    // Extra delay for reset to fully complete
    i = 0;
    while (i < 100000) : (i += 1) {
        asm volatile ("pause");
    }

    // PCI bus master must be enabled via pci_enable_bus_master after init

    // Disable interrupts again after reset
    writeReg(base, REG_IMC, 0xFFFFFFFF);
    _ = readReg(base, REG_ICR);

    // Set link up
    writeReg(base, REG_CTRL, readReg(base, REG_CTRL) | CTRL_SLU | CTRL_ASDE);

    // Clear multicast table
    i = 0;
    while (i < 128) : (i += 1) {
        writeReg(base, REG_MTA + i * 4, 0);
    }

    // ── RX ring setup ───────────────────────────────────────────────────
    i = 0;
    while (i < NUM_RX_DESC) : (i += 1) {
        p.rx_descs[i].buffer_addr = p.rx_bufs_dma_base + @as(u64, i) * PACKET_BUF_SIZE;
        p.rx_descs[i].status = 0;
    }

    writeReg(base, REG_RDBAL, @truncate(p.rx_descs_dma));
    writeReg(base, REG_RDBAH, @truncate(p.rx_descs_dma >> 32));
    writeReg(base, REG_RDLEN, @sizeOf(RxDesc) * NUM_RX_DESC);
    writeReg(base, REG_RDH, 0);

    // Enable RX first, then set RDT to activate the ring
    const rctl_val = RCTL_EN | RCTL_BAM | RCTL_SECRC | (1 << 3) | (1 << 4);
    writeReg(base, REG_RCTL, rctl_val);

    // Now set RDT after RCTL.EN is set
    writeReg(base, REG_RDT, NUM_RX_DESC - 1);

    // ── TX ring setup ───────────────────────────────────────────────────
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

    writeReg(base, REG_TCTL, TCTL_EN | TCTL_PSP | (15 << 4) | (64 << 12));

    // Enable RX interrupts to wake QEMU's e1000 receive path.
    // Without this, QEMU may stop delivering packets after the first one.
    writeReg(base, REG_IMS, 0xFF); // Enable all common interrupts

    return true;
}

// ── RX poll ─────────────────────────────────────────────────────────────

pub const RxResult = struct {
    index: u5,
    len: u16,
};

/// Check for a received packet. Returns the buffer index and length.
/// Does NOT return the buffer to the RX ring — caller must do that
/// after processing (or after zero-copy TX completes).
pub fn rxPoll(
    rx_descs: *[NUM_RX_DESC]RxDesc,
    rx_tail: *u32,
) ?RxResult {
    const next = (rx_tail.* + 1) % NUM_RX_DESC;
    // Read the status through a cast to ensure the compiler doesn't elide this
    const desc_ptr = @intFromPtr(rx_descs) + @as(usize, next) * @sizeOf(RxDesc);
    const status_ptr: *const volatile u8 = @ptrFromInt(desc_ptr + 12); // offset of status field
    const status_val = status_ptr.*;
    if (status_val & RX_DESC_DD == 0) return null;
    const desc = &rx_descs[next];

    const len = desc.length;
    desc.status = 0;
    rx_tail.* = next;

    return .{ .index = @truncate(next), .len = len };
}

/// Return an RX buffer to the hardware ring so it can receive again.
/// Also clears any pending interrupt to allow QEMU to deliver more packets.
pub fn rxReturn(mmio_base: u64, rx_tail: u32) void {
    writeReg(mmio_base, REG_RDT, rx_tail);
    _ = readReg(mmio_base, REG_ICR); // Clear pending interrupts
}

// ── TX ──────────────────────────────────────────────────────────────────

/// Send a packet by pointing a TX descriptor at an arbitrary DMA address.
/// Used for zero-copy forwarding (pointing at the other NIC's RX buffer).
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
/// Used for locally-generated packets (ARP, DHCP, ICMP replies).
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

    // Copy data into the TX buffer
    const buf_virt = tx_bufs_virt_base + @as(u64, idx) * PACKET_BUF_SIZE;
    const dst: [*]u8 = @ptrFromInt(buf_virt);
    @memcpy(dst[0..data.len], data);

    // Point descriptor at the TX buffer's DMA address
    desc.buffer_addr = dma_base + @as(u64, idx) * PACKET_BUF_SIZE;
    desc.length = @intCast(data.len);
    desc.cmd = TX_DESC_CMD_EOP | TX_DESC_CMD_IFCS | TX_DESC_CMD_RS;
    desc.status = 0;

    tx_tail.* = (tx_tail.* + 1) % NUM_TX_DESC;
    writeReg(mmio_base, REG_TDT, tx_tail.*);
    return true;
}

/// Check if a TX descriptor has completed (for zero-copy buffer reclamation).
pub fn txDone(tx_descs: *[NUM_TX_DESC]TxDesc, idx: u32) bool {
    return @as(*volatile u8, &tx_descs[idx].status).* & TX_DESC_STA_DD != 0;
}

// ── Interrupt status ───────────────────────────────────────────────────

/// Clear pending interrupt status (read-to-clear).
pub fn clearIrq(mmio_base: u64) void {
    _ = readReg(mmio_base, REG_ICR);
}

// ── Link status ────────────────────────────────────────────────────────

pub fn linkUp(mmio_base: u64) bool {
    return (readReg(mmio_base, REG_STATUS) & 0x02) != 0;
}
