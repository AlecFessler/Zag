const router = @import("router");

const main = router.state;
const util = router.util;

pub const CONN_TABLE_SIZE = 256;

const ConnState = enum(u8) { empty = 0, active = 1, expired = 2 };

const TCP_ESTABLISHED_TIMEOUT_NS: u64 = 300_000_000_000;
const TCP_OTHER_TIMEOUT_NS: u64 = 30_000_000_000;
const UDP_TIMEOUT_NS: u64 = 120_000_000_000;
const ICMPV6_TIMEOUT_NS: u64 = 60_000_000_000;

pub const ConnEntry = struct {
    state: u8 align(8) = @intFromEnum(ConnState.empty),
    protocol: u8 = 0,
    src_port: u16 = 0,
    dst_port: u16 = 0,
    src_ip6: [16]u8 = .{0} ** 16,
    dst_ip6: [16]u8 = .{0} ** 16,
    timestamp_ns: u64 = 0,
    tcp_state: u8 = 0,
};

pub const empty = ConnEntry{};

fn hash(protocol: u8, ip6: [16]u8, port: u16) u32 {
    var h: u32 = @as(u32, protocol) *% 31;
    h +%= @as(u32, ip6[12]) *% 257;
    h +%= @as(u32, ip6[13]) *% 1031;
    h +%= @as(u32, ip6[14]) *% 4099;
    h +%= @as(u32, ip6[15]) *% 16411;
    h +%= @as(u32, port) *% 65537;
    return h & (CONN_TABLE_SIZE - 1);
}

/// Track an outbound (LAN→WAN) connection.
pub fn allowOutbound(pkt: []const u8, len: u32) void {
    if (len < 54) return;
    const next_header = pkt[20];
    if (next_header != 6 and next_header != 17) return;

    const transport_start: usize = 54;
    if (transport_start + 4 > len) return;

    var src_ip6: [16]u8 = undefined;
    var dst_ip6: [16]u8 = undefined;
    @memcpy(&src_ip6, pkt[22..38]);
    @memcpy(&dst_ip6, pkt[38..54]);
    const src_port = util.readU16Be(pkt[transport_start..][0..2]);
    const dst_port = util.readU16Be(pkt[transport_start + 2 ..][0..2]);

    const now = util.now();
    const idx = hash(next_header, src_ip6, src_port);

    // Check if entry exists
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const slot = (idx + i) & (CONN_TABLE_SIZE - 1);
        const e = &main.conn6_table[slot];
        const st = @atomicLoad(u8, &e.state, .acquire);
        if (st == @intFromEnum(ConnState.active) and
            e.protocol == next_header and
            util.eql(&e.src_ip6, &src_ip6) and
            e.src_port == src_port)
        {
            e.timestamp_ns = now;
            return;
        }
        if (st == @intFromEnum(ConnState.empty)) break;
    }

    // Create new entry
    i = 0;
    while (i < 8) : (i += 1) {
        const slot = (idx + i) & (CONN_TABLE_SIZE - 1);
        const e = &main.conn6_table[slot];
        const st = @atomicLoad(u8, &e.state, .acquire);
        if (st != @intFromEnum(ConnState.active)) {
            e.protocol = next_header;
            @memcpy(&e.src_ip6, &src_ip6);
            @memcpy(&e.dst_ip6, &dst_ip6);
            e.src_port = src_port;
            e.dst_port = dst_port;
            e.timestamp_ns = now;
            @atomicStore(u8, &e.state, @intFromEnum(ConnState.active), .release);
            return;
        }
    }
}

/// Check if inbound (WAN→LAN) traffic matches a tracked connection.
pub fn allowInbound(pkt: []const u8, len: u32) bool {
    if (len < 54) return false;
    const next_header = pkt[20];

    // Always allow essential ICMPv6
    if (next_header == 58) return isAllowedIcmpv6(pkt, len);

    if (next_header != 6 and next_header != 17) return false;

    const transport_start: usize = 54;
    if (transport_start + 4 > len) return false;

    // For inbound, src/dst are swapped relative to the outbound entry
    var src_ip6: [16]u8 = undefined;
    var dst_ip6: [16]u8 = undefined;
    @memcpy(&src_ip6, pkt[22..38]); // remote source
    @memcpy(&dst_ip6, pkt[38..54]); // LAN destination
    const src_port = util.readU16Be(pkt[transport_start..][0..2]);
    const dst_port = util.readU16Be(pkt[transport_start + 2 ..][0..2]);

    // Look up by (LAN dst = original src, LAN dst_port = original src_port)
    const idx = hash(next_header, dst_ip6, dst_port);
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const slot = (idx + i) & (CONN_TABLE_SIZE - 1);
        const e = &main.conn6_table[slot];
        const st = @atomicLoad(u8, &e.state, .acquire);
        if (st == @intFromEnum(ConnState.active) and
            e.protocol == next_header and
            util.eql(&e.src_ip6, &dst_ip6) and
            e.src_port == dst_port and
            util.eql(&e.dst_ip6, &src_ip6) and
            e.dst_port == src_port)
        {
            e.timestamp_ns = util.now();
            return true;
        }
        if (st == @intFromEnum(ConnState.empty)) break;
    }
    return false;
}

fn isAllowedIcmpv6(pkt: []const u8, len: u32) bool {
    if (len < 55) return false;
    const icmpv6_type = pkt[54];
    // Allow error messages (types 1-4)
    if (icmpv6_type >= 1 and icmpv6_type <= 4) return true;
    // Allow echo request/reply (128-129)
    if (icmpv6_type == 128 or icmpv6_type == 129) return true;
    // Allow NDP (133-137)
    if (icmpv6_type >= 133 and icmpv6_type <= 137) return true;
    return false;
}

pub fn expire() void {
    const now = util.now();
    for (&main.conn6_table) |*e| {
        if (@atomicLoad(u8, &e.state, .acquire) != @intFromEnum(ConnState.active)) continue;
        const timeout = if (e.protocol == 6) TCP_ESTABLISHED_TIMEOUT_NS else if (e.protocol == 17) UDP_TIMEOUT_NS else ICMPV6_TIMEOUT_NS;
        if (now -% e.timestamp_ns > timeout) {
            @atomicStore(u8, &e.state, @intFromEnum(ConnState.expired), .release);
        }
    }
}
