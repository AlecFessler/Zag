/// Virtio-net device emulation (virtio v1.2, device ID 1).
/// Implements a virtual network card using split virtqueues over MMIO transport.
/// The MMIO transport layer is built separately — this module provides the
/// device-specific logic: config space, TX processing, and RX injection.
///
/// Spec reference: virtio v1.2 section 5.1 "Network Device"
///   - Config layout: section 5.1.4
///   - Packet header: section 5.1.6 (struct virtio_net_hdr)
///   - TX path: section 5.1.6.2
///   - RX path: section 5.1.6.3, 5.1.6.4

const log = @import("log.zig");
const mem = @import("mem.zig");

// ---------------------------------------------------------------------------
// Feature bits (virtio v1.2 section 5.1.3)
// ---------------------------------------------------------------------------

/// Device has given MAC address in config space.
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;

/// Mergeable receive buffers — header includes num_buffers field (12 bytes).
pub const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;

/// Configuration status field is available.
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;

/// Non-legacy modern interface (virtio 1.0+).
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// ---------------------------------------------------------------------------
// Net header flags / GSO types (virtio v1.2 section 5.1.6)
// ---------------------------------------------------------------------------

pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;
pub const VIRTIO_NET_HDR_F_RSC_INFO: u8 = 4;

pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_UDP: u8 = 3;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

// ---------------------------------------------------------------------------
// Link status bits (virtio v1.2 section 5.1.4)
// ---------------------------------------------------------------------------

pub const VIRTIO_NET_S_LINK_UP: u16 = 1;
pub const VIRTIO_NET_S_ANNOUNCE: u16 = 2;

// ---------------------------------------------------------------------------
// Virtqueue descriptor flags (virtio v1.2 section 2.7.5)
// ---------------------------------------------------------------------------

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// Virtqueue geometry
// ---------------------------------------------------------------------------

/// Queue size — power of two, up to 32768. 256 is typical for net devices.
pub const QUEUE_SIZE: u16 = 256;

/// Number of virtqueues: 0=receiveq, 1=transmitq.
pub const NUM_QUEUES: u8 = 2;

// ---------------------------------------------------------------------------
// Header sizes
// ---------------------------------------------------------------------------

/// With VIRTIO_NET_F_MRG_RXBUF: 12 bytes (includes num_buffers).
pub const NET_HDR_SIZE_MRG: usize = 12;

/// Without VIRTIO_NET_F_MRG_RXBUF: 10 bytes.
pub const NET_HDR_SIZE: usize = 10;

// ---------------------------------------------------------------------------
// Virtqueue ring element structures
//
// Split virtqueue layout (virtio v1.2 section 2.7):
//   Descriptor Table: 16 bytes per entry
//   Available Ring:   6 + 2 * queue_size bytes
//   Used Ring:        6 + 8 * queue_size bytes
// ---------------------------------------------------------------------------

/// Read a 16-byte descriptor from guest memory.
/// struct virtq_desc { le64 addr; le32 len; le16 flags; le16 next; }
const VirtqDesc = struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

noinline fn readDesc(desc_table: u64, index: u16) VirtqDesc {
    const base = desc_table + @as(u64, index) * 16;
    const slice = mem.readGuestSlice(base, 16);
    return .{
        .addr = readU64(slice[0..8]),
        .len = readU32(slice[8..12]),
        .flags = readU16(slice[12..14]),
        .next = readU16(slice[14..16]),
    };
}

/// Read avail ring idx: at avail_base + 2 (after flags field).
fn readAvailIdx(avail_base: u64) u16 {
    const slice = mem.readGuestSlice(avail_base + 2, 2);
    return readU16(slice[0..2]);
}

/// Read avail ring entry: at avail_base + 4 + 2*index.
fn readAvailRing(avail_base: u64, index: u16) u16 {
    const off = avail_base + 4 + @as(u64, index) * 2;
    const slice = mem.readGuestSlice(off, 2);
    return readU16(slice[0..2]);
}

/// Read used ring idx: at used_base + 2 (after flags field).
fn readUsedIdx(used_base: u64) u16 {
    const slice = mem.readGuestSlice(used_base + 2, 2);
    return readU16(slice[0..2]);
}

/// Write used ring idx: at used_base + 2.
fn writeUsedIdx(used_base: u64, idx: u16) void {
    var buf: [2]u8 = undefined;
    putU16(&buf, idx);
    mem.writeGuest(used_base + 2, &buf);
}

/// Write a used ring element: at used_base + 4 + 8*index.
/// struct virtq_used_elem { le32 id; le32 len; }
fn writeUsedElem(used_base: u64, ring_idx: u16, desc_id: u32, len: u32) void {
    const off = used_base + 4 + @as(u64, ring_idx) * 8;
    var buf: [8]u8 = undefined;
    putU32(buf[0..4], desc_id);
    putU32(buf[4..8], len);
    mem.writeGuest(off, &buf);
}

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------

fn readU16(b: *const [2]u8) u16 {
    return @as(u16, b[0]) | (@as(u16, b[1]) << 8);
}

fn readU32(b: *const [4]u8) u32 {
    return @as(u32, b[0]) |
        (@as(u32, b[1]) << 8) |
        (@as(u32, b[2]) << 16) |
        (@as(u32, b[3]) << 24);
}

fn readU64(b: *const [8]u8) u64 {
    return @as(u64, readU32(b[0..4])) | (@as(u64, readU32(b[4..8])) << 32);
}

fn putU16(b: *[2]u8, v: u16) void {
    b[0] = @truncate(v);
    b[1] = @truncate(v >> 8);
}

fn putU32(b: *[4]u8, v: u32) void {
    b[0] = @truncate(v);
    b[1] = @truncate(v >> 8);
    b[2] = @truncate(v >> 16);
    b[3] = @truncate(v >> 24);
}

// ---------------------------------------------------------------------------
// Device state
// ---------------------------------------------------------------------------

pub const VirtioNet = struct {
    mac: [6]u8,
    status: u16,
    features: u64,

    /// Per-queue state: guest physical addresses of ring components.
    /// Index 0 = receiveq, 1 = transmitq.
    desc_table: [NUM_QUEUES]u64,
    avail_ring: [NUM_QUEUES]u64,
    used_ring: [NUM_QUEUES]u64,

    /// Device-side tracking of last-processed available index per queue.
    last_avail_idx: [NUM_QUEUES]u16,

    /// Device-side used index per queue (shadows the used ring idx field).
    used_idx: [NUM_QUEUES]u16,

    /// Interrupt status register (bit 0 = used buffer notification).
    interrupt_status: u32,

    /// TX packet counter for logging.
    tx_count: u64,

    /// RX packet counter for logging.
    rx_count: u64,
};

// ---------------------------------------------------------------------------
// File-scope global instance
// ---------------------------------------------------------------------------

var device: VirtioNet = undefined;

/// Scratch buffer for collecting TX frame data from descriptor chains.
/// Max Ethernet frame = 1514 + virtio_net_hdr (12) = 1526, round up.
var tx_scratch: [2048]u8 = undefined;

/// Scratch buffer for building RX frames (header + payload).
var rx_scratch: [2048]u8 = undefined;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the virtio-net device with a given MAC address.
/// Link is reported as up. Features offered: MAC, STATUS, MRG_RXBUF, VERSION_1.
pub fn init(mac: [6]u8) void {
    device = .{
        .mac = mac,
        .status = VIRTIO_NET_S_LINK_UP,
        .features = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_NET_F_MRG_RXBUF | VIRTIO_F_VERSION_1,
        .desc_table = .{ 0, 0 },
        .avail_ring = .{ 0, 0 },
        .used_ring = .{ 0, 0 },
        .last_avail_idx = .{ 0, 0 },
        .used_idx = .{ 0, 0 },
        .interrupt_status = 0,
        .tx_count = 0,
        .rx_count = 0,
    };

    log.print("virtio-net: init mac=");
    for (mac, 0..) |b, i| {
        log.hex8(b);
        if (i < 5) log.print(":");
    }
    log.print("\n");
}

/// Return the offered feature bits for this device.
pub fn getFeatures() u64 {
    return device.features;
}

/// Set the queue addresses after the driver configures them via MMIO transport.
/// queue_idx: 0=receiveq, 1=transmitq.
pub fn setQueueAddrs(queue_idx: u8, desc: u64, avail: u64, used: u64) void {
    if (queue_idx >= NUM_QUEUES) return;
    device.desc_table[queue_idx] = desc;
    device.avail_ring[queue_idx] = avail;
    device.used_ring[queue_idx] = used;

    log.print("virtio-net: q");
    log.dec(queue_idx);
    log.print(" desc=0x");
    log.hex64(desc);
    log.print(" avail=0x");
    log.hex64(avail);
    log.print(" used=0x");
    log.hex64(used);
    log.print("\n");
}

/// Read device config space at the given offset (relative to MMIO 0x100).
/// Returns a 32-bit value; sub-word fields are packed into the low bits.
///
/// Config layout (virtio v1.2 section 5.1.4):
///   offset 0x00: mac[0..3]  (4 bytes of MAC)
///   offset 0x04: mac[4..5] + status (mac[4], mac[5], status_lo, status_hi)
pub noinline fn getConfig(offset: u32) u32 {
    // Config space is only 8 bytes (6 MAC + 2 status) for our feature set.
    switch (offset) {
        0x00 => {
            // mac[0..3]
            return @as(u32, device.mac[0]) |
                (@as(u32, device.mac[1]) << 8) |
                (@as(u32, device.mac[2]) << 16) |
                (@as(u32, device.mac[3]) << 24);
        },
        0x04 => {
            // mac[4..5] + status
            return @as(u32, device.mac[4]) |
                (@as(u32, device.mac[5]) << 8) |
                (@as(u32, device.status) << 16);
        },
        else => {
            log.print("virtio-net: config read at unknown offset 0x");
            log.hex32(offset);
            log.print("\n");
            return 0;
        },
    }
}

/// Read the interrupt status register. The MMIO transport calls this on
/// InterruptStatus read. Bit 0 = used buffer notification.
pub fn getInterruptStatus() u32 {
    return device.interrupt_status;
}

/// Acknowledge (clear) interrupt status bits. Called when the driver writes
/// to InterruptACK in the MMIO transport.
pub fn ackInterrupt(ack: u32) void {
    device.interrupt_status &= ~ack;
}

/// Process pending TX packets from transmitq (queue index 1).
///
/// TX path (virtio v1.2 section 5.1.6.2):
///   1. Read descriptor chain from available ring
///   2. First bytes are struct virtio_net_hdr (12 bytes with MRG_RXBUF)
///   3. Remaining bytes are the Ethernet frame
///   4. Add descriptor head to used ring
///   5. Set interrupt status bit 0
pub noinline fn processTx() void {
    const qi: u8 = 1; // transmitq

    if (device.desc_table[qi] == 0) return;

    const avail_idx = readAvailIdx(device.avail_ring[qi]);

    while (device.last_avail_idx[qi] != avail_idx) {
        const ring_slot = device.last_avail_idx[qi] % QUEUE_SIZE;
        const head = readAvailRing(device.avail_ring[qi], ring_slot);

        // Walk the descriptor chain, collecting data into tx_scratch.
        var total_len: usize = 0;
        var desc_idx = head;
        var chain_len: u32 = 0;
        while (true) {
            const desc = readDesc(device.desc_table[qi], desc_idx);
            const copy_len = @min(desc.len, tx_scratch.len - total_len);
            if (copy_len > 0) {
                const src = mem.readGuestSlice(desc.addr, copy_len);
                @memcpy(tx_scratch[total_len..][0..copy_len], src);
                total_len += copy_len;
            }
            chain_len += desc.len;

            if (desc.flags & VIRTQ_DESC_F_NEXT == 0) break;
            desc_idx = desc.next;
        }

        // Skip the virtio_net_hdr to get the Ethernet frame.
        const hdr_size = NET_HDR_SIZE_MRG;
        if (total_len > hdr_size) {
            const frame_len = total_len - hdr_size;
            // Log first few TX packets for debugging.
            if (device.tx_count < 5) {
                log.print("virtio-net: TX ");
                log.dec(frame_len);
                log.print(" bytes");
                // Print dst MAC from the Ethernet header.
                if (frame_len >= 14) {
                    log.print(" dst=");
                    for (0..6) |i| {
                        log.hex8(tx_scratch[hdr_size + i]);
                        if (i < 5) log.print(":");
                    }
                }
                log.print("\n");
            }
        }
        device.tx_count += 1;

        // Add to used ring: report 0 bytes written (TX has no device-writable part).
        const used_slot = device.used_idx[qi] % QUEUE_SIZE;
        writeUsedElem(device.used_ring[qi], used_slot, head, 0);
        device.used_idx[qi] +%= 1;
        writeUsedIdx(device.used_ring[qi], device.used_idx[qi]);

        device.last_avail_idx[qi] +%= 1;
    }

    // Signal used buffer notification.
    device.interrupt_status |= 1;
}

/// Inject a received Ethernet frame into the guest via receiveq (queue index 0).
///
/// RX path (virtio v1.2 section 5.1.6.3, 5.1.6.4):
///   1. Guest pre-posts empty buffers in receiveq
///   2. Device writes virtio_net_hdr + frame data into the next available buffer
///   3. Sets num_buffers=1 (single buffer, with MRG_RXBUF)
///   4. Adds to used ring with total written length
///   5. Sets interrupt status bit 0
pub noinline fn injectRx(frame: []const u8) void {
    const qi: u8 = 0; // receiveq

    if (device.desc_table[qi] == 0) return;

    const avail_idx = readAvailIdx(device.avail_ring[qi]);
    if (device.last_avail_idx[qi] == avail_idx) {
        // No receive buffers available — drop the packet.
        log.print("virtio-net: RX drop, no buffers\n");
        return;
    }

    // Build the packet: zero header + frame data.
    const hdr_size = NET_HDR_SIZE_MRG;
    const total = hdr_size + frame.len;
    if (total > rx_scratch.len) {
        log.print("virtio-net: RX drop, frame too large\n");
        return;
    }

    // Zero the header.
    for (rx_scratch[0..hdr_size]) |*b| b.* = 0;
    // Set num_buffers = 1 at offset 10 (le16) per virtio v1.2 section 5.1.6.
    rx_scratch[10] = 1;
    rx_scratch[11] = 0;
    // Copy frame data after header.
    @memcpy(rx_scratch[hdr_size..][0..frame.len], frame);

    // Get the next available receive buffer descriptor.
    const ring_slot = device.last_avail_idx[qi] % QUEUE_SIZE;
    const head = readAvailRing(device.avail_ring[qi], ring_slot);

    // Write the packet into the descriptor chain.
    var written: usize = 0;
    var desc_idx = head;
    while (written < total) {
        const desc = readDesc(device.desc_table[qi], desc_idx);

        // Only write to device-writable descriptors.
        if (desc.flags & VIRTQ_DESC_F_WRITE != 0) {
            const chunk = @min(desc.len, @as(u32, @intCast(total - written)));
            mem.writeGuest(desc.addr, rx_scratch[written..][0..chunk]);
            written += chunk;
        }

        if (desc.flags & VIRTQ_DESC_F_NEXT == 0) break;
        desc_idx = desc.next;
    }

    // Add to used ring with total bytes written.
    const used_slot = device.used_idx[qi] % QUEUE_SIZE;
    writeUsedElem(device.used_ring[qi], used_slot, head, @intCast(written));
    device.used_idx[qi] +%= 1;
    writeUsedIdx(device.used_ring[qi], device.used_idx[qi]);

    device.last_avail_idx[qi] +%= 1;
    device.rx_count += 1;

    // Signal used buffer notification.
    device.interrupt_status |= 1;

    if (device.rx_count <= 5) {
        log.print("virtio-net: RX ");
        log.dec(frame.len);
        log.print(" bytes\n");
    }
}
