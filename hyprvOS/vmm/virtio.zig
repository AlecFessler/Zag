/// virtio-mmio transport layer (virtio v1.2, Section 4.2).
/// Implements the MMIO register interface shared by all virtio devices.
/// The guest discovers this device via kernel command line:
///   virtio_mmio.device=0x200@0xD0000000:5
///
/// All registers are little-endian 32-bit aligned (Section 4.2.2).
/// Device-specific config space starts at offset 0x100.

const mem = @import("mem.zig");
const log = @import("log.zig");

// ── MMIO Register Offsets (Table 4.1) ────────────────────────────────

const REG_MAGIC: u32 = 0x000; // R  — 0x74726976 ("virt")
const REG_VERSION: u32 = 0x004; // R  — 0x2
const REG_DEVICE_ID: u32 = 0x008; // R  — device type (2=blk)
const REG_VENDOR_ID: u32 = 0x00C; // R  — 0x554D4551 ("QEMU")
const REG_DEVICE_FEATURES: u32 = 0x010; // R  — features[sel*32 +: 32]
const REG_DEVICE_FEATURES_SEL: u32 = 0x014; // W
const REG_DRIVER_FEATURES: u32 = 0x020; // W
const REG_DRIVER_FEATURES_SEL: u32 = 0x024; // W
const REG_QUEUE_SEL: u32 = 0x030; // W
const REG_QUEUE_NUM_MAX: u32 = 0x034; // R
const REG_QUEUE_NUM: u32 = 0x038; // W
const REG_QUEUE_READY: u32 = 0x044; // RW
const REG_QUEUE_NOTIFY: u32 = 0x050; // W
const REG_INTERRUPT_STATUS: u32 = 0x060; // R
const REG_INTERRUPT_ACK: u32 = 0x064; // W
const REG_STATUS: u32 = 0x070; // RW
const REG_QUEUE_DESC_LOW: u32 = 0x080; // W
const REG_QUEUE_DESC_HIGH: u32 = 0x084; // W
const REG_QUEUE_DRIVER_LOW: u32 = 0x090; // W
const REG_QUEUE_DRIVER_HIGH: u32 = 0x094; // W
const REG_QUEUE_DEVICE_LOW: u32 = 0x0A0; // W
const REG_QUEUE_DEVICE_HIGH: u32 = 0x0A4; // W
const REG_CONFIG_GENERATION: u32 = 0x0FC; // R
const REG_CONFIG_START: u32 = 0x100; // RW — device-specific config

// ── MMIO Constants ───────────────────────────────────────────────────

const MAGIC_VALUE: u32 = 0x74726976; // "virt" in LE
const VERSION: u32 = 0x2; // Non-legacy modern device
const VENDOR_ID: u32 = 0x554D4551; // "QEMU" — conventional

// ── Device Status Bits (Section 2.1) ─────────────────────────────────

pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_NEEDS_RESET: u8 = 64;
pub const STATUS_FAILED: u8 = 128;

// ── Virtqueue Constants ──────────────────────────────────────────────

pub const MAX_QUEUES: usize = 4;
pub const DEFAULT_QUEUE_NUM_MAX: u16 = 256;

// ── Split Virtqueue Descriptor Flags (Section 2.7.5) ─────────────────

pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;

// ── Interrupt Status Bits (Section 4.2.2) ────────────────────────────

const INTERRUPT_USED_BUFFER: u32 = 1; // bit 0: used buffer notification
const INTERRUPT_CONFIG_CHANGE: u32 = 2; // bit 1: config change

// ── Common Feature Bits (Section 6) ──────────────────────────────────

pub const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1 << 28;
pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// ── MMIO Device Base Address ─────────────────────────────────────────
// Matches kernel command line: virtio_mmio.device=0x200@0xD0000000:5

pub const VIRTIO_MMIO_BASE: u64 = 0xD0000000;
pub const VIRTIO_MMIO_SIZE: u64 = 0x200;
pub const VIRTIO_MMIO_IRQ: u8 = 5;

// ── Split Virtqueue Structures (Section 2.7) ─────────────────────────
// These match the guest memory layout. All fields are little-endian.

/// Virtqueue descriptor (Section 2.7.5): 16 bytes each.
pub const VirtqDesc = extern struct {
    addr: u64, // Guest-physical address of buffer
    len: u32, // Length of buffer in bytes
    flags: u16, // VIRTQ_DESC_F_* flags
    next: u16, // Index of next descriptor if F_NEXT
};

/// Used ring element (Section 2.7.8): 8 bytes.
pub const VirtqUsedElem = extern struct {
    id: u32, // Head of descriptor chain
    len: u32, // Bytes written by device
};

// ── Virtqueue State ──────────────────────────────────────────────────

pub const VirtqueueState = struct {
    num: u16 = 0, // Queue size (set by driver)
    ready: bool = false,

    // Guest-physical addresses of the three ring areas
    desc_addr: u64 = 0, // Descriptor Table GPA
    driver_addr: u64 = 0, // Available Ring GPA
    device_addr: u64 = 0, // Used Ring GPA

    // Device-side tracking
    last_avail_idx: u16 = 0, // Next index to read from available ring
};

// ── Notify Callback ──────────────────────────────────────────────────
// Device-specific handler called when the driver writes to QueueNotify.

pub const NotifyFn = *const fn (queue_index: u32) void;

// ── Config Space Callback ────────────────────────────────────────────
// Device-specific handlers for config space reads/writes at offset 0x100+.

pub const ConfigReadFn = *const fn (offset: u32) u32;
pub const ConfigWriteFn = *const fn (offset: u32, value: u32) void;

// ── VirtioMmioDevice ────────────────────────────────────────────────

pub const VirtioMmioDevice = struct {
    // Identity
    device_id: u32, // e.g. 2 for blk, 1 for net

    // Feature negotiation
    device_features: u64 = 0, // Features offered by device
    driver_features: u64 = 0, // Features accepted by driver
    device_features_sel: u32 = 0, // Word selector for device features read
    driver_features_sel: u32 = 0, // Word selector for driver features write

    // Device status (Section 2.1)
    status: u8 = 0,

    // Interrupt state
    interrupt_status: u32 = 0,

    // Queue selection
    queue_sel: u32 = 0,

    // Virtqueue state (up to MAX_QUEUES)
    queues: [MAX_QUEUES]VirtqueueState = [_]VirtqueueState{.{}} ** MAX_QUEUES,
    num_queues: u32 = 1, // How many queues this device exposes

    // Config generation counter (Section 2.5)
    config_generation: u32 = 0,

    // Device-specific callbacks
    notify_fn: NotifyFn,
    config_read_fn: ConfigReadFn,
    config_write_fn: ConfigWriteFn,

    // ── MMIO Register Read (Section 4.2.2) ──────────────────────

    /// Handle a 32-bit MMIO read at the given offset from base.
    /// Returns the register value. Called from EPT violation handler.
    pub noinline fn mmioRead(self: *VirtioMmioDevice, offset: u32) u32 {
        return switch (offset) {
            REG_MAGIC => MAGIC_VALUE,
            REG_VERSION => VERSION,
            REG_DEVICE_ID => self.device_id,
            REG_VENDOR_ID => VENDOR_ID,
            REG_DEVICE_FEATURES => self.readDeviceFeatures(),
            REG_QUEUE_NUM_MAX => self.readQueueNumMax(),
            REG_QUEUE_READY => self.readQueueReady(),
            REG_INTERRUPT_STATUS => self.interrupt_status,
            REG_STATUS => @as(u32, self.status),
            REG_CONFIG_GENERATION => self.config_generation,
            else => blk: {
                if (offset >= REG_CONFIG_START) {
                    break :blk self.config_read_fn(offset - REG_CONFIG_START);
                }
                break :blk 0;
            },
        };
    }

    /// Handle a 32-bit MMIO write at the given offset from base.
    /// Called from EPT violation handler.
    pub noinline fn mmioWrite(self: *VirtioMmioDevice, offset: u32, value: u32) void {
        switch (offset) {
            REG_DEVICE_FEATURES_SEL => self.device_features_sel = value,
            REG_DRIVER_FEATURES => self.writeDriverFeatures(value),
            REG_DRIVER_FEATURES_SEL => self.driver_features_sel = value,
            REG_QUEUE_SEL => {
                if (value < MAX_QUEUES) self.queue_sel = value;
            },
            REG_QUEUE_NUM => self.writeQueueNum(value),
            REG_QUEUE_READY => self.writeQueueReady(value),
            REG_QUEUE_NOTIFY => self.notify_fn(value),
            REG_INTERRUPT_ACK => {
                // Clear acknowledged interrupt bits (Section 4.2.2)
                self.interrupt_status &= ~value;
            },
            REG_STATUS => self.writeStatus(value),
            REG_QUEUE_DESC_LOW => self.writeQueueDescLow(value),
            REG_QUEUE_DESC_HIGH => self.writeQueueDescHigh(value),
            REG_QUEUE_DRIVER_LOW => self.writeQueueDriverLow(value),
            REG_QUEUE_DRIVER_HIGH => self.writeQueueDriverHigh(value),
            REG_QUEUE_DEVICE_LOW => self.writeQueueDeviceLow(value),
            REG_QUEUE_DEVICE_HIGH => self.writeQueueDeviceHigh(value),
            else => {
                if (offset >= REG_CONFIG_START) {
                    self.config_write_fn(offset - REG_CONFIG_START, value);
                }
            },
        }
    }

    // ── Register Helpers ─────────────────────────────────────────

    fn readDeviceFeatures(self: *const VirtioMmioDevice) u32 {
        // Return 32-bit window into the 64-bit feature bits, selected
        // by device_features_sel (Section 4.2.2, DeviceFeatures).
        if (self.device_features_sel == 0) {
            return @truncate(self.device_features);
        } else if (self.device_features_sel == 1) {
            return @truncate(self.device_features >> 32);
        }
        return 0;
    }

    fn writeDriverFeatures(self: *VirtioMmioDevice, value: u32) void {
        if (self.driver_features_sel == 0) {
            self.driver_features = (self.driver_features & 0xFFFFFFFF00000000) | @as(u64, value);
        } else if (self.driver_features_sel == 1) {
            self.driver_features = (self.driver_features & 0x00000000FFFFFFFF) | (@as(u64, value) << 32);
        }
    }

    fn readQueueNumMax(self: *const VirtioMmioDevice) u32 {
        if (self.queue_sel < self.num_queues) return DEFAULT_QUEUE_NUM_MAX;
        return 0; // Queue not available
    }

    fn readQueueReady(self: *const VirtioMmioDevice) u32 {
        if (self.queue_sel < MAX_QUEUES) {
            return if (self.queues[self.queue_sel].ready) 1 else 0;
        }
        return 0;
    }

    fn writeQueueNum(self: *VirtioMmioDevice, value: u32) void {
        if (self.queue_sel < MAX_QUEUES and !self.queues[self.queue_sel].ready) {
            const num: u16 = @truncate(value);
            if (num <= DEFAULT_QUEUE_NUM_MAX) {
                self.queues[self.queue_sel].num = num;
            }
        }
    }

    fn writeQueueReady(self: *VirtioMmioDevice, value: u32) void {
        if (self.queue_sel < MAX_QUEUES) {
            self.queues[self.queue_sel].ready = (value & 1) != 0;
        }
    }

    fn writeStatus(self: *VirtioMmioDevice, value: u32) void {
        if (value == 0) {
            // Writing zero triggers a device reset (Section 4.2.2, Status).
            self.reset();
            return;
        }
        self.status = @truncate(value);
    }

    fn writeQueueDescLow(self: *VirtioMmioDevice, value: u32) void {
        if (self.queue_sel < MAX_QUEUES) {
            const q = &self.queues[self.queue_sel];
            q.desc_addr = (q.desc_addr & 0xFFFFFFFF00000000) | @as(u64, value);
        }
    }

    fn writeQueueDescHigh(self: *VirtioMmioDevice, value: u32) void {
        if (self.queue_sel < MAX_QUEUES) {
            const q = &self.queues[self.queue_sel];
            q.desc_addr = (q.desc_addr & 0x00000000FFFFFFFF) | (@as(u64, value) << 32);
        }
    }

    fn writeQueueDriverLow(self: *VirtioMmioDevice, value: u32) void {
        if (self.queue_sel < MAX_QUEUES) {
            const q = &self.queues[self.queue_sel];
            q.driver_addr = (q.driver_addr & 0xFFFFFFFF00000000) | @as(u64, value);
        }
    }

    fn writeQueueDriverHigh(self: *VirtioMmioDevice, value: u32) void {
        if (self.queue_sel < MAX_QUEUES) {
            const q = &self.queues[self.queue_sel];
            q.driver_addr = (q.driver_addr & 0x00000000FFFFFFFF) | (@as(u64, value) << 32);
        }
    }

    fn writeQueueDeviceLow(self: *VirtioMmioDevice, value: u32) void {
        if (self.queue_sel < MAX_QUEUES) {
            const q = &self.queues[self.queue_sel];
            q.device_addr = (q.device_addr & 0xFFFFFFFF00000000) | @as(u64, value);
        }
    }

    fn writeQueueDeviceHigh(self: *VirtioMmioDevice, value: u32) void {
        if (self.queue_sel < MAX_QUEUES) {
            const q = &self.queues[self.queue_sel];
            q.device_addr = (q.device_addr & 0x00000000FFFFFFFF) | (@as(u64, value) << 32);
        }
    }

    // ── Device Reset (Section 4.2.2) ─────────────────────────────

    fn reset(self: *VirtioMmioDevice) void {
        self.status = 0;
        self.interrupt_status = 0;
        self.device_features_sel = 0;
        self.driver_features_sel = 0;
        self.driver_features = 0;
        self.queue_sel = 0;
        for (&self.queues) |*q| {
            q.* = .{};
        }
    }

    // ── Interrupt Signaling ──────────────────────────────────────

    /// Signal a used buffer notification (bit 0 of InterruptStatus).
    /// The VMM should inject the corresponding IRQ into the guest.
    pub fn signalUsedBuffer(self: *VirtioMmioDevice) void {
        self.interrupt_status |= INTERRUPT_USED_BUFFER;
    }

    // ── Virtqueue Helpers ────────────────────────────────────────
    // These read/write split virtqueue structures from guest physical
    // memory using the GPAs configured by the driver.

    /// Read a descriptor from the descriptor table at the given index.
    /// Descriptor table starts at desc_addr, each entry is 16 bytes
    /// (Section 2.7.5).
    pub noinline fn readDescriptor(q: *const VirtqueueState, index: u16) VirtqDesc {
        const desc_gpa = q.desc_addr + @as(u64, index) * 16;
        const slice = mem.readGuestSlice(desc_gpa, @sizeOf(VirtqDesc));
        return @as(*align(1) const VirtqDesc, @ptrCast(slice.ptr)).*;
    }

    /// Read the next available descriptor head index from the available
    /// ring (Section 2.7.6).
    /// Available ring layout: flags(u16) | idx(u16) | ring[QueueNum](u16) | used_event(u16)
    pub noinline fn readAvailIdx(q: *const VirtqueueState) u16 {
        // idx is at offset 2 in the available ring
        const gpa = q.driver_addr + 2;
        const slice = mem.readGuestSlice(gpa, 2);
        return @as(*align(1) const u16, @ptrCast(slice.ptr)).*;
    }

    /// Read an entry from the available ring at the given ring position.
    pub noinline fn readAvailRing(q: *const VirtqueueState, ring_idx: u16) u16 {
        // ring[] starts at offset 4 in the available ring
        const gpa = q.driver_addr + 4 + @as(u64, ring_idx) * 2;
        const slice = mem.readGuestSlice(gpa, 2);
        return @as(*align(1) const u16, @ptrCast(slice.ptr)).*;
    }

    /// Write an entry to the used ring (Section 2.7.8).
    /// Used ring layout: flags(u16) | idx(u16) | ring[QueueNum](UsedElem) | avail_event(u16)
    pub noinline fn writeUsedElem(q: *const VirtqueueState, ring_idx: u16, elem: VirtqUsedElem) void {
        // ring[] starts at offset 4 in the used ring, each elem is 8 bytes
        const gpa = q.device_addr + 4 + @as(u64, ring_idx) * 8;
        const bytes: *const [8]u8 = @ptrCast(&elem);
        mem.writeGuest(gpa, bytes);
    }

    /// Read the current used ring idx field.
    pub noinline fn readUsedIdx(q: *const VirtqueueState) u16 {
        const gpa = q.device_addr + 2;
        const slice = mem.readGuestSlice(gpa, 2);
        return @as(*align(1) const u16, @ptrCast(slice.ptr)).*;
    }

    /// Update the used ring idx field.
    pub noinline fn writeUsedIdx(q: *const VirtqueueState, idx: u16) void {
        const gpa = q.device_addr + 2;
        const bytes: *const [2]u8 = @ptrCast(&idx);
        mem.writeGuest(gpa, bytes);
    }

    /// Check if the given queue has pending buffers to process.
    pub fn queueHasPending(q: *const VirtqueueState) bool {
        if (!q.ready or q.num == 0) return false;
        const avail_idx = readAvailIdx(q);
        return avail_idx != q.last_avail_idx;
    }
};
