/// virtio-blk device emulation (virtio v1.2, Section 5.2).
/// Implements a virtual block device backed by NVMe physical storage.
/// Uses the virtio-mmio transport from virtio.zig.
///
/// Device ID: 2 (Section 5.2.1)
/// Virtqueues: 1 — requestq at index 0 (Section 5.2.2)
///
/// Request format (Section 5.2.6):
///   Descriptor 0: virtio_blk_req header (16 bytes, device-readable)
///     le32 type — VIRTIO_BLK_T_IN (0), _OUT (1), _FLUSH (4)
///     le32 reserved
///     le64 sector
///   Descriptor 1..N-1: data buffers
///   Descriptor N: status byte (1 byte, device-writable)
///     0 = OK, 1 = IOERR, 2 = UNSUPP

const mem = @import("mem.zig");
const log = @import("log.zig");
const nvme = @import("nvme.zig");
const virtio = @import("virtio.zig");

// ── Block Request Types (Section 5.2.6) ──────────────────────────────

const VIRTIO_BLK_T_IN: u32 = 0; // Read from device
const VIRTIO_BLK_T_OUT: u32 = 1; // Write to device
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_GET_ID: u32 = 8;

// ── Block Status Codes (Section 5.2.6) ───────────────────────────────

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

// ── Feature Bits (Section 5.2.3) ─────────────────────────────────────

const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

// ── Config Space Layout (Section 5.2.4) ──────────────────────────────
// Offsets from 0x100 (start of device-specific config in MMIO):
//   0x00: capacity    (le64)  — device size in 512-byte sectors
//   0x08: size_max    (le32)  — max single segment size
//   0x0C: seg_max     (le32)  — max segments per request
//   0x10: geometry    (4 bytes: cylinders(u16), heads(u8), sectors(u8))
//   0x14: blk_size    (le32)  — logical block size

const SECTOR_SIZE: u64 = 512;
const MAX_SEG_SIZE: u32 = 4096; // Single-page transfers via NVMe DMA buffer
const MAX_SEGMENTS: u32 = 126; // Reasonable limit for descriptor chains

// ── Config Space (file-scope to avoid stack overflow) ────────────────

var config_space: [64]u8 = [_]u8{0} ** 64;

// ── Device ID String (Section 5.2.6, VIRTIO_BLK_T_GET_ID) ───────────

const device_id_string: [20]u8 = blk: {
    var id: [20]u8 = [_]u8{0} ** 20;
    const s = "zagvirtblk0";
    for (s, 0..) |c, i| {
        id[i] = c;
    }
    break :blk id;
};

// ── Request Header (Section 5.2.6) ──────────────────────────────────

const BlkReqHeader = extern struct {
    req_type: u32, // VIRTIO_BLK_T_*
    reserved: u32,
    sector: u64,
};

// ── Convenience aliases ──────────────────────────────────────────────

const Mmio = virtio.VirtioMmioDevice;
const QState = virtio.VirtqueueState;

// ── VirtioBlk ────────────────────────────────────────────────────────

pub const VirtioBlk = struct {
    mmio: virtio.VirtioMmioDevice,
    nvme_ctrl: *nvme.Controller,
    capacity_sectors: u64,
    nvme_nsid: u32 = 1,

    /// Initialize a virtio-blk device with the given NVMe backing store.
    pub fn init(nvme_ctrl: *nvme.Controller, capacity_sectors: u64) VirtioBlk {
        // Build config space: capacity + size_max + seg_max + blk_size
        writeLeU64(&config_space, 0x00, capacity_sectors);
        writeLeU32(&config_space, 0x08, MAX_SEG_SIZE);
        writeLeU32(&config_space, 0x0C, MAX_SEGMENTS);
        // geometry: CHS (not meaningful for virtual device)
        writeLeU16(&config_space, 0x10, 0); // cylinders
        config_space[0x12] = 0; // heads
        config_space[0x13] = 0; // sectors
        writeLeU32(&config_space, 0x14, 512); // blk_size

        const device_features =
            VIRTIO_BLK_F_SIZE_MAX |
            VIRTIO_BLK_F_SEG_MAX |
            VIRTIO_BLK_F_FLUSH |
            VIRTIO_BLK_F_BLK_SIZE |
            virtio.VIRTIO_F_VERSION_1;

        return VirtioBlk{
            .mmio = .{
                .device_id = 2, // Block device (Section 5.2.1)
                .device_features = device_features,
                .num_queues = 1, // Single requestq
                .notify_fn = &notifyHandler,
                .config_read_fn = &configRead,
                .config_write_fn = &configWrite,
            },
            .nvme_ctrl = nvme_ctrl,
            .capacity_sectors = capacity_sectors,
        };
    }

    /// Process all pending requests from the requestq (queue 0).
    /// Called when the driver writes to QueueNotify with queue index 0.
    pub noinline fn processQueue(self: *VirtioBlk) void {
        const q = &self.mmio.queues[0];
        if (!q.ready or q.num == 0) return;

        while (Mmio.queueHasPending(q)) {
            // Read the head descriptor index from the available ring.
            const ring_idx = q.last_avail_idx % q.num;
            const head = Mmio.readAvailRing(q, ring_idx);
            q.last_avail_idx +%= 1;

            const bytes_written = self.handleRequest(q, head);

            // Add to used ring (Section 2.7.8).
            const used_idx = Mmio.readUsedIdx(q);
            Mmio.writeUsedElem(q, used_idx % q.num, .{
                .id = head,
                .len = bytes_written,
            });
            Mmio.writeUsedIdx(q, used_idx +% 1);
        }

        // Signal used buffer notification
        self.mmio.signalUsedBuffer();
    }

    /// Process a single request starting at the given descriptor chain head.
    /// Returns total bytes written to device-writable descriptors.
    noinline fn handleRequest(self: *VirtioBlk, q: *const QState, head: u16) u32 {
        // Walk the descriptor chain:
        //   desc[0]: header (device-readable, 16 bytes)
        //   desc[1..N-1]: data buffers
        //   desc[N]: status byte (device-writable, 1 byte)

        var desc_idx = head;

        // 1. Read the request header from the first descriptor.
        const hdr_desc = Mmio.readDescriptor(q, desc_idx);
        if (hdr_desc.len < @sizeOf(BlkReqHeader)) {
            return writeStatusToLast(q, head, VIRTIO_BLK_S_IOERR);
        }

        const hdr_slice = mem.readGuestSlice(hdr_desc.addr, @sizeOf(BlkReqHeader));
        const hdr: BlkReqHeader = @as(*align(1) const BlkReqHeader, @ptrCast(hdr_slice.ptr)).*;

        // Advance past header descriptor (must have F_NEXT set).
        if (hdr_desc.flags & virtio.VIRTQ_DESC_F_NEXT == 0) {
            return writeStatusToLast(q, head, VIRTIO_BLK_S_IOERR);
        }
        desc_idx = hdr_desc.next;

        // 2. Dispatch based on request type.
        return switch (hdr.req_type) {
            VIRTIO_BLK_T_IN => self.handleRead(q, desc_idx, hdr.sector),
            VIRTIO_BLK_T_OUT => self.handleWrite(q, desc_idx, hdr.sector),
            VIRTIO_BLK_T_FLUSH => self.handleFlush(q, desc_idx),
            VIRTIO_BLK_T_GET_ID => handleGetId(q, desc_idx),
            else => walkToStatus(q, desc_idx, VIRTIO_BLK_S_UNSUPP),
        };
    }

    /// VIRTIO_BLK_T_IN: Read sectors from NVMe, write data to guest buffers.
    noinline fn handleRead(self: *VirtioBlk, q: *const QState, start_idx: u16, start_sector: u64) u32 {
        var desc_idx = start_idx;
        var sector = start_sector;
        var bytes_written: u32 = 0;
        var status: u8 = VIRTIO_BLK_S_OK;

        while (true) {
            const desc = Mmio.readDescriptor(q, desc_idx);

            // Last descriptor (no F_NEXT) is the status byte.
            if (desc.flags & virtio.VIRTQ_DESC_F_NEXT == 0) {
                const s = [1]u8{status};
                mem.writeGuest(desc.addr, &s);
                bytes_written += 1;
                break;
            }

            // Data buffer — read sectors from NVMe into guest memory.
            if (status == VIRTIO_BLK_S_OK) {
                const result = self.nvmeReadToGuest(desc.addr, desc.len, sector);
                if (!result.ok) status = VIRTIO_BLK_S_IOERR;
                bytes_written += result.bytes;
                sector += result.sectors;
            }

            desc_idx = desc.next;
        }

        return bytes_written;
    }

    /// VIRTIO_BLK_T_OUT: Read data from guest buffers, write to NVMe.
    noinline fn handleWrite(self: *VirtioBlk, q: *const QState, start_idx: u16, start_sector: u64) u32 {
        var desc_idx = start_idx;
        var sector = start_sector;
        var bytes_written: u32 = 0;
        var status: u8 = VIRTIO_BLK_S_OK;

        while (true) {
            const desc = Mmio.readDescriptor(q, desc_idx);

            // Last descriptor (no F_NEXT) is the status byte.
            if (desc.flags & virtio.VIRTQ_DESC_F_NEXT == 0) {
                const s = [1]u8{status};
                mem.writeGuest(desc.addr, &s);
                bytes_written += 1;
                break;
            }

            // Data buffer — write guest data to NVMe.
            if (status == VIRTIO_BLK_S_OK) {
                const result = self.nvmeWriteFromGuest(desc.addr, desc.len, sector);
                if (!result.ok) status = VIRTIO_BLK_S_IOERR;
                sector += result.sectors;
            }

            desc_idx = desc.next;
        }

        return bytes_written;
    }

    /// VIRTIO_BLK_T_FLUSH: Commit writes to persistent storage.
    noinline fn handleFlush(self: *VirtioBlk, q: *const QState, start_idx: u16) u32 {
        var status: u8 = VIRTIO_BLK_S_OK;
        if (!self.nvme_ctrl.flush(self.nvme_nsid)) {
            status = VIRTIO_BLK_S_IOERR;
        }
        return walkToStatus(q, start_idx, status);
    }

    // ── NVMe Transfer Helpers ────────────────────────────────────

    const XferResult = struct {
        ok: bool,
        bytes: u32, // Bytes transferred to/from guest
        sectors: u64, // Sectors consumed
    };

    /// Read from NVMe and copy into guest memory at guest_addr.
    /// Transfers data_len bytes starting at the given sector.
    /// NVMe DMA buffer is 4096 bytes (8 sectors), so we batch.
    noinline fn nvmeReadToGuest(self: *VirtioBlk, guest_addr: u64, data_len: u32, sector: u64) XferResult {
        var offset: u32 = 0;
        var cur_sector = sector;
        const sectors_total = (@as(u64, data_len) + SECTOR_SIZE - 1) / SECTOR_SIZE;

        var secs_left: u64 = sectors_total;
        while (secs_left > 0) {
            const batch: u16 = @intCast(@min(secs_left, 8));

            if (cur_sector + batch > self.capacity_sectors) {
                return .{ .ok = false, .bytes = offset, .sectors = cur_sector - sector };
            }

            if (!self.nvme_ctrl.readSectors(self.nvme_nsid, cur_sector, batch)) {
                return .{ .ok = false, .bytes = offset, .sectors = cur_sector - sector };
            }

            const copy_len: u32 = @intCast(@min(@as(u64, batch) * SECTOR_SIZE, data_len - offset));
            const src = nvme.dataBuffer(self.nvme_ctrl);
            mem.writeGuest(guest_addr + offset, src[0..copy_len]);

            offset += copy_len;
            cur_sector += batch;
            secs_left -= batch;
        }

        return .{ .ok = true, .bytes = offset, .sectors = sectors_total };
    }

    /// Copy from guest memory and write to NVMe starting at the given sector.
    noinline fn nvmeWriteFromGuest(self: *VirtioBlk, guest_addr: u64, data_len: u32, sector: u64) XferResult {
        var offset: u32 = 0;
        var cur_sector = sector;
        const sectors_total = (@as(u64, data_len) + SECTOR_SIZE - 1) / SECTOR_SIZE;

        var secs_left: u64 = sectors_total;
        while (secs_left > 0) {
            const batch: u16 = @intCast(@min(secs_left, 8));

            if (cur_sector + batch > self.capacity_sectors) {
                return .{ .ok = false, .bytes = offset, .sectors = cur_sector - sector };
            }

            const copy_len: u32 = @intCast(@min(@as(u64, batch) * SECTOR_SIZE, data_len - offset));
            const guest_data = mem.readGuestSlice(guest_addr + offset, copy_len);
            const dst = self.nvme_ctrl.dataBufferMut();
            @memcpy(dst[0..copy_len], guest_data);

            // Zero-pad partial sector so NVMe gets clean data.
            const batch_bytes: u32 = @as(u32, batch) * @as(u32, @intCast(SECTOR_SIZE));
            if (copy_len < batch_bytes) {
                @memset(dst[copy_len..batch_bytes], 0);
            }

            if (!self.nvme_ctrl.writeSectors(self.nvme_nsid, cur_sector, batch)) {
                return .{ .ok = false, .bytes = offset, .sectors = cur_sector - sector };
            }

            offset += copy_len;
            cur_sector += batch;
            secs_left -= batch;
        }

        return .{ .ok = true, .bytes = offset, .sectors = sectors_total };
    }
};

// ── Free Functions (callbacks and helpers) ────────────────────────────

/// VIRTIO_BLK_T_GET_ID: Write device ID string to guest buffer.
noinline fn handleGetId(q: *const QState, start_idx: u16) u32 {
    var desc_idx = start_idx;
    var bytes_written: u32 = 0;

    while (true) {
        const d = Mmio.readDescriptor(q, desc_idx);

        if (d.flags & virtio.VIRTQ_DESC_F_NEXT == 0) {
            // Status descriptor — write OK.
            const s = [1]u8{VIRTIO_BLK_S_OK};
            mem.writeGuest(d.addr, &s);
            bytes_written += 1;
            break;
        }

        // Data descriptor — write device ID string.
        if (d.flags & virtio.VIRTQ_DESC_F_WRITE != 0) {
            const write_len: u32 = @min(d.len, 20);
            mem.writeGuest(d.addr, device_id_string[0..write_len]);
            bytes_written += write_len;
        }
        desc_idx = d.next;
    }

    return bytes_written;
}

/// Walk a descriptor chain to the last descriptor and write a status byte.
/// Used for flush, unsupported types, and error paths.
noinline fn walkToStatus(q: *const QState, start_idx: u16, status: u8) u32 {
    var desc_idx = start_idx;
    var guard: u32 = 0;
    while (guard < 256) : (guard += 1) {
        const d = Mmio.readDescriptor(q, desc_idx);
        if (d.flags & virtio.VIRTQ_DESC_F_NEXT == 0) {
            const s = [1]u8{status};
            mem.writeGuest(d.addr, &s);
            return 1;
        }
        desc_idx = d.next;
    }
    return 0;
}

/// Walk from the very start of a chain (head) to the last descriptor.
/// Used when the header itself is malformed.
noinline fn writeStatusToLast(q: *const QState, head: u16, status: u8) u32 {
    return walkToStatus(q, head, status);
}

// ── Notify Handler (called from virtio-mmio transport) ───────────────

/// File-scope pointer to the single blk device instance.
/// Set via setInstance() during VMM initialization.
var blk_instance: ?*VirtioBlk = null;

pub fn setInstance(instance: *VirtioBlk) void {
    blk_instance = instance;
}

fn notifyHandler(queue_index: u32) void {
    if (queue_index != 0) return; // Only requestq (queue 0) is valid
    if (blk_instance) |blk| {
        blk.processQueue();
    }
}

// ── Config Space Read/Write (Section 5.2.4) ──────────────────────────

fn configRead(offset: u32) u32 {
    if (offset + 4 > config_space.len) return 0;
    return @as(*align(1) const u32, @ptrCast(config_space[offset..].ptr)).*;
}

fn configWrite(offset: u32, value: u32) void {
    // Config space is mostly read-only for blk.
    // writeback field (offset 0x20) could be written if CONFIG_WCE
    // is negotiated, but we don't offer it.
    _ = offset;
    _ = value;
}

// ── Little-endian helpers for config space ────────────────────────────

fn writeLeU64(buf: []u8, offset: usize, value: u64) void {
    @as(*align(1) u64, @ptrCast(buf.ptr + offset)).* = value;
}

fn writeLeU32(buf: []u8, offset: usize, value: u32) void {
    @as(*align(1) u32, @ptrCast(buf.ptr + offset)).* = value;
}

fn writeLeU16(buf: []u8, offset: usize, value: u16) void {
    @as(*align(1) u16, @ptrCast(buf.ptr + offset)).* = value;
}
