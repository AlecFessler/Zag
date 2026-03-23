const std = @import("std");
const crc32 = @import("crc32.zig");
const syscall = @import("syscall.zig");

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

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
        const header_size = @sizeOf(ChannelHeader);
        const usable = total_size - header_size;
        const per_ring = usable / 2;
        const ring_data = per_ring - @sizeOf(RingHeader);

        self.magic = CHANNEL_MAGIC;
        self.version = 1;
        self.flags = 0;
        self.ring_a_offset = header_size;
        self.ring_b_offset = header_size + per_ring;
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

pub const RingHeader = extern struct {
    head: u64 align(8),
    tail: u64 align(8),
    wake_flag: u64 align(8),
    checksum: u32,
    data_size: u32,

    pub fn init(self: *RingHeader) void {
        self.head = 0;
        self.tail = 0;
        self.wake_flag = 0;
        self.checksum = 0;
        self.data_size = 0;
    }

    fn dataPtr(self: *RingHeader) [*]u8 {
        return @ptrFromInt(@intFromPtr(self) + @sizeOf(RingHeader));
    }

    /// Message format in ring: [u32 length][u32 crc32][u8 data...]
    /// The CRC covers the data bytes only.
    pub fn write(self: *RingHeader, ring_size: u32, data: []const u8) bool {
        const head = @atomicLoad(u64, &self.head, .acquire);
        const tail = @as(*volatile u64, &self.tail).*;
        const used = tail -% head;
        const free = ring_size - used;

        // Message envelope: 4 bytes length + 4 bytes CRC + data
        const msg_size = @sizeOf(u32) + @sizeOf(u32) + data.len;
        if (msg_size > free) return false;

        const buf = self.dataPtr();
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

        @atomicStore(u64, &self.tail, tail +% msg_size, .release);

        _ = @atomicRmw(u64, &self.wake_flag, .Add, 1, .release);
        _ = syscall.futex_wake(&self.wake_flag, 1);

        return true;
    }

    pub fn read(self: *RingHeader, ring_size: u32, out: []u8) ?u32 {
        const head = @as(*volatile u64, &self.head).*;
        const tail = @atomicLoad(u64, &self.tail, .acquire);

        if (head == tail) return null;

        const buf = self.dataPtr();
        var pos = head % ring_size;

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

        const new_head = head +% @sizeOf(u32) +% @sizeOf(u32) +% msg_len;
        @atomicStore(u64, &self.head, new_head, .release);

        return msg_len;
    }

    pub fn waitForData(self: *RingHeader) void {
        while (@as(*volatile u64, &self.head).* == @atomicLoad(u64, &self.tail, .acquire)) {
            const current = @atomicLoad(u64, &self.wake_flag, .acquire);
            if (@as(*volatile u64, &self.head).* != @atomicLoad(u64, &self.tail, .acquire)) break;
            _ = syscall.futex_wait(&self.wake_flag, current, MAX_TIMEOUT);
        }
    }

    pub fn hasData(self: *RingHeader) bool {
        return @as(*volatile u64, &self.head).* != @atomicLoad(u64, &self.tail, .acquire);
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

    pub fn openAsSideB(base: *ChannelHeader) ?Channel {
        if (!base.isValid()) return null;
        return .{
            .header = base,
            .tx = base.ringB(),
            .rx = base.ringA(),
            .ring_size = base.ring_size,
        };
    }

    pub fn send(self: *Channel, data: []const u8) bool {
        return self.tx.write(self.ring_size, data);
    }

    pub fn recv(self: *Channel, out: []u8) ?u32 {
        return self.rx.read(self.ring_size, out);
    }

    pub fn waitForMessage(self: *Channel) void {
        self.rx.waitForData();
    }

    pub fn hasMessage(self: *Channel) bool {
        return self.rx.hasData();
    }
};
