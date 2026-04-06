const std = @import("std");
const crc32 = @import("crc32.zig");
const syscall = @import("syscall.zig");

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
const CACHE_LINE = 64;

pub const CHANNEL_MAGIC: u64 = 0x5A41475F4348414E;

pub const ChannelHeader = extern struct {
    magic: u64,
    version: u16,
    flags: u16,
    ring_a_offset: u32,
    ring_b_offset: u32,
    ring_size: u32,
    _reserved: u32,

    pub fn init(self: *ChannelHeader, total_size: u32) void {
        // Ring offsets must be 64-byte aligned for cache-line separation
        const ring_a_off = std.mem.alignForward(u32, @sizeOf(ChannelHeader), CACHE_LINE);
        const remaining = total_size - ring_a_off;
        const per_ring_raw = remaining / 2;
        const per_ring = std.mem.alignBackward(u32, per_ring_raw, CACHE_LINE);
        const ring_b_off = ring_a_off + per_ring;
        const ring_data = per_ring - @sizeOf(RingHeader);

        self.magic = CHANNEL_MAGIC;
        self.version = 1;
        self.flags = 0;
        self.ring_a_offset = ring_a_off;
        self.ring_b_offset = ring_b_off;
        self.ring_size = ring_data;
        self._reserved = 0;

        self.ringA().init();
        self.ringB().init();
    }

    pub fn isValid(self: *const ChannelHeader) bool {
        return self.magic == CHANNEL_MAGIC and self.version == 1;
    }

    pub fn ringA(self: *ChannelHeader) *RingHeader {
        return @ptrFromInt(@intFromPtr(self) + self.ring_a_offset);
    }

    pub fn ringB(self: *ChannelHeader) *RingHeader {
        return @ptrFromInt(@intFromPtr(self) + self.ring_b_offset);
    }
};

/// Ring header with cache-line-separated producer and consumer fields.
///
/// Cache line 0 (producer-owned): tail + cached_head
/// Cache line 1 (consumer-owned): head + cached_tail
///
/// The producer only touches cache line 1 when the queue appears full
/// (to reload the remote head). The consumer only touches cache line 0
/// when the queue appears empty (to reload the remote tail).
pub const RingHeader = extern struct {
    // ── Cache line 0: producer-owned ─────────────────────────
    tail: u64 align(CACHE_LINE) = 0,
    cached_head: u64 = 0,
    _pad_producer: [CACHE_LINE - 16]u8 = .{0} ** (CACHE_LINE - 16),

    // ── Cache line 1: consumer-owned ─────────────────────────
    head: u64 align(CACHE_LINE) = 0,
    cached_tail: u64 = 0,
    _pad_consumer: [CACHE_LINE - 16]u8 = .{0} ** (CACHE_LINE - 16),

    // ── Metadata ─────────────────────────────────────────────
    data_size: u32 = 0,
    _reserved: u32 = 0,

    comptime {
        if (@offsetOf(RingHeader, "tail") / CACHE_LINE == @offsetOf(RingHeader, "head") / CACHE_LINE)
            @compileError("tail and head must be on different cache lines");
        if (@offsetOf(RingHeader, "tail") / CACHE_LINE != @offsetOf(RingHeader, "cached_head") / CACHE_LINE)
            @compileError("tail and cached_head must share a cache line");
        if (@offsetOf(RingHeader, "head") / CACHE_LINE != @offsetOf(RingHeader, "cached_tail") / CACHE_LINE)
            @compileError("head and cached_tail must share a cache line");
    }

    pub fn init(self: *RingHeader) void {
        self.tail = 0;
        self.cached_head = 0;
        self.head = 0;
        self.cached_tail = 0;
        self.data_size = 0;
        self._reserved = 0;
    }

    fn dataPtr(self: *RingHeader) [*]u8 {
        return @ptrFromInt(@intFromPtr(self) + @sizeOf(RingHeader));
    }

    /// Wait until the ring has data, or the timeout expires.
    /// Waits directly on the tail cursor — the producer calls
    /// futex_wake(&tail) after each write.
    pub fn waitForData(self: *RingHeader, timeout_ns: u64) void {
        const head_val = self.head;
        const tail_val = @atomicLoad(u64, &self.tail, .acquire);
        if (head_val != tail_val) return;
        _ = syscall.futex_wait(&self.tail, tail_val, timeout_ns);
    }

    pub fn hasData(self: *RingHeader) bool {
        return self.head != @atomicLoad(u64, &self.tail, .acquire);
    }
};

pub const Channel = struct {
    header: *ChannelHeader,
    tx: *RingHeader,
    rx: *RingHeader,
    ring_size: u32,

    pub fn initAsSideA(base: *ChannelHeader, total_size: u32) Channel {
        base.init(total_size);
        return .{
            .header = base,
            .tx = base.ringA(),
            .rx = base.ringB(),
            .ring_size = base.ring_size,
        };
    }

    pub fn openAsSideA(base: *ChannelHeader) ?Channel {
        if (!base.isValid()) return null;
        return .{
            .header = base,
            .tx = base.ringA(),
            .rx = base.ringB(),
            .ring_size = base.ring_size,
        };
    }

    pub fn openAsSideB(base: *ChannelHeader) ?Channel {
        if (!base.isValid()) return null;
        return .{
            .header = base,
            .tx = base.ringB(),
            .rx = base.ringA(),
            .ring_size = base.ring_size,
        };
    }

    /// Send a message. Uses cached head to avoid cross-core atomic loads
    /// unless the ring appears full.
    ///
    /// Message format: [u32 length][u32 crc32][u8 data...]
    pub fn send(self: *Channel, data: []const u8) bool {
        const ring = self.tx;
        const ring_size = self.ring_size;

        const tail = ring.tail;
        const msg_size: u64 = @sizeOf(u32) + @sizeOf(u32) + data.len;

        // Fast path: check cached head
        var free = ring_size -% (tail -% ring.cached_head);
        if (msg_size > free) {
            // Slow path: reload remote head
            ring.cached_head = @atomicLoad(u64, &ring.head, .acquire);
            free = ring_size -% (tail -% ring.cached_head);
            if (msg_size > free) return false;
        }

        const buf = ring.dataPtr();
        const len_bytes = std.mem.toBytes(@as(u32, @intCast(data.len)));
        const msg_crc = crc32.compute(data);
        const crc_bytes = std.mem.toBytes(msg_crc);

        var pos = tail % ring_size;
        for (len_bytes) |b| {
            buf[pos] = b;
            pos = (pos + 1) % ring_size;
        }
        for (crc_bytes) |b| {
            buf[pos] = b;
            pos = (pos + 1) % ring_size;
        }
        for (data) |b| {
            buf[pos] = b;
            pos = (pos + 1) % ring_size;
        }

        @atomicStore(u64, &ring.tail, tail +% msg_size, .release);
        _ = syscall.futex_wake(&ring.tail, 1);

        return true;
    }

    /// Receive a message. Uses cached tail to avoid cross-core atomic loads
    /// unless the ring appears empty.
    pub fn recv(self: *Channel, out: []u8) ?u32 {
        const ring = self.rx;
        const ring_size = self.ring_size;

        const head_val = ring.head;

        // Fast path: check cached tail
        if (head_val == ring.cached_tail) {
            // Slow path: reload remote tail
            ring.cached_tail = @atomicLoad(u64, &ring.tail, .acquire);
            if (head_val == ring.cached_tail) return null;
        }

        const buf = ring.dataPtr();
        var pos = head_val % ring_size;

        // Read message length
        var len_bytes: [4]u8 = undefined;
        for (&len_bytes) |*b| {
            b.* = buf[pos];
            pos = (pos + 1) % ring_size;
        }
        const msg_len = std.mem.bytesToValue(u32, &len_bytes);

        if (msg_len > out.len) return null;

        // Read stored CRC
        var crc_bytes: [4]u8 = undefined;
        for (&crc_bytes) |*b| {
            b.* = buf[pos];
            pos = (pos + 1) % ring_size;
        }
        const stored_crc = std.mem.bytesToValue(u32, &crc_bytes);

        // Read message data
        for (out[0..msg_len]) |*b| {
            b.* = buf[pos];
            pos = (pos + 1) % ring_size;
        }

        // Verify CRC
        const actual_crc = crc32.compute(out[0..msg_len]);
        if (stored_crc != actual_crc) return null;

        const new_head = head_val +% @sizeOf(u32) +% @sizeOf(u32) +% msg_len;
        @atomicStore(u64, &ring.head, new_head, .release);

        return msg_len;
    }

    pub fn waitForMessage(self: *Channel, timeout_ns: u64) void {
        self.rx.waitForData(timeout_ns);
    }

    pub fn hasMessage(self: *Channel) bool {
        return self.rx.hasData();
    }
};
