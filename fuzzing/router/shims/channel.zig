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
};

pub const RingHeader = extern struct {
    tail: u64 align(CACHE_LINE) = 0,
    cached_head: u64 = 0,
    _pad_producer: [CACHE_LINE - 16]u8 = .{0} ** (CACHE_LINE - 16),

    head: u64 align(CACHE_LINE) = 0,
    cached_tail: u64 = 0,
    _pad_consumer: [CACHE_LINE - 16]u8 = .{0} ** (CACHE_LINE - 16),

    data_size: u32 = 0,
    _reserved: u32 = 0,
};

pub const Channel = struct {
    header: *ChannelHeader,
    tx: *RingHeader,
    rx: *RingHeader,
    ring_size: u32,

    pub fn send(_: *Channel, _: []const u8) bool {
        return false;
    }

    pub fn recv(_: *Channel, _: []u8) ?u32 {
        return null;
    }

    pub fn hasMessage(_: *Channel) bool {
        return false;
    }

    pub fn waitForMessage(_: *Channel, _: u64) void {}
};
