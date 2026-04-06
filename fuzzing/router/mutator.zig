/// AFL++-style mutation engine for network packets.
/// Takes a valid seed packet and applies structured mutations that are
/// likely to trigger edge cases in protocol parsing.
const std = @import("std");
const packet_gen = @import("packet_gen.zig");

const GeneratedPacket = packet_gen.GeneratedPacket;

pub const MutationType = enum {
    bit_flip,
    interesting_8,
    interesting_16,
    arithmetic_16,
    length_havoc,
    protocol_confusion,
    address_boundary,
    tcp_options_corrupt,
    truncate,
};

// AFL++ interesting values
const interesting_8 = [_]u8{ 0, 1, 0x7F, 0x80, 0xFF };
const interesting_16 = [_]u16{ 0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF };

// Protocol-significant offsets in Ethernet + IPv4 + TCP packet
const header_offsets_8 = [_]usize{
    14, // IP ver_ihl
    15, // IP TOS
    22, // TTL
    23, // protocol
};

const header_offsets_16 = [_]struct { off: usize, desc: []const u8 }{
    .{ .off = 16, .desc = "ip_total_len" },
    .{ .off = 18, .desc = "ip_id" },
    .{ .off = 20, .desc = "ip_flags_frag" },
    .{ .off = 24, .desc = "ip_checksum" },
    .{ .off = 34, .desc = "src_port" },
    .{ .off = 36, .desc = "dst_port" },
};

const boundary_ips = [_][4]u8{
    .{ 0, 0, 0, 0 }, // unspecified
    .{ 127, 0, 0, 1 }, // loopback
    .{ 10, 1, 1, 1 }, // router LAN IP
    .{ 10, 0, 2, 15 }, // router WAN IP
    .{ 255, 255, 255, 255 }, // broadcast
    .{ 224, 0, 0, 1 }, // multicast
    .{ 10, 1, 1, 255 }, // LAN broadcast
    .{ 10, 0, 2, 1 }, // WAN gateway
    .{ 169, 254, 1, 1 }, // link-local
    .{ 0, 0, 0, 1 }, // near-zero
};

/// Apply a random AFL++-style mutation to a valid seed packet.
/// Returns the mutated packet with is_mutated=true.
pub fn mutate(random: std.Random, seed: GeneratedPacket) GeneratedPacket {
    var pkt = seed;
    pkt.is_mutated = true;

    const strategy = random.intRangeLessThan(u8, 0, 20);
    switch (strategy) {
        0...3 => bitFlip(random, &pkt),
        4...6 => interestingValue8(random, &pkt),
        7...9 => interestingValue16(random, &pkt),
        10...12 => arithmetic16(random, &pkt),
        13...14 => lengthHavoc(random, &pkt),
        15 => protocolConfusion(random, &pkt),
        16...17 => addressBoundary(random, &pkt),
        18 => tcpOptionsCorrupt(random, &pkt),
        19 => truncatePacket(random, &pkt),
        else => bitFlip(random, &pkt),
    }

    return pkt;
}

fn bitFlip(random: std.Random, pkt: *GeneratedPacket) void {
    if (pkt.len == 0) return;
    // Focus on header region (first 54 bytes) 80% of the time
    const max_off = if (random.float(f32) < 0.8)
        @min(pkt.len, 54)
    else
        pkt.len;
    if (max_off == 0) return;
    const byte_idx = random.intRangeLessThan(u32, 0, max_off);
    const bit_idx: u3 = @truncate(random.intRangeLessThan(u8, 0, 8));

    // Flip 1, 2, or 4 consecutive bits
    const flip_count = switch (random.intRangeLessThan(u2, 0, 3)) {
        0 => @as(u3, 1),
        1 => @as(u3, 2),
        else => @as(u3, 4),
    };

    var i: u3 = 0;
    while (i < flip_count) : (i += 1) {
        const actual_bit: u3 = bit_idx +% i;
        pkt.buf[byte_idx] ^= @as(u8, 1) << actual_bit;
    }
}

fn interestingValue8(random: std.Random, pkt: *GeneratedPacket) void {
    if (pkt.len < 24) return;
    // Pick a protocol-significant offset
    const off_idx = random.intRangeLessThan(usize, 0, header_offsets_8.len);
    const offset = header_offsets_8[off_idx];
    if (offset >= pkt.len) return;
    const val_idx = random.intRangeLessThan(usize, 0, interesting_8.len);
    pkt.buf[offset] = interesting_8[val_idx];
}

fn interestingValue16(random: std.Random, pkt: *GeneratedPacket) void {
    if (pkt.len < 38) return;
    const off_idx = random.intRangeLessThan(usize, 0, header_offsets_16.len);
    const offset = header_offsets_16[off_idx].off;
    if (offset + 1 >= pkt.len) return;
    const val_idx = random.intRangeLessThan(usize, 0, interesting_16.len);
    const val = interesting_16[val_idx];
    pkt.buf[offset] = @truncate(val >> 8);
    pkt.buf[offset + 1] = @truncate(val);
}

fn arithmetic16(random: std.Random, pkt: *GeneratedPacket) void {
    if (pkt.len < 38) return;
    const off_idx = random.intRangeLessThan(usize, 0, header_offsets_16.len);
    const offset = header_offsets_16[off_idx].off;
    if (offset + 1 >= pkt.len) return;

    // Read current value, add/subtract 1-35 (AFL++ range)
    var val: u16 = @as(u16, pkt.buf[offset]) << 8 | pkt.buf[offset + 1];
    const delta: u16 = random.intRangeAtMost(u16, 1, 35);
    if (random.boolean()) {
        val +%= delta;
    } else {
        val -%= delta;
    }
    pkt.buf[offset] = @truncate(val >> 8);
    pkt.buf[offset + 1] = @truncate(val);
}

fn lengthHavoc(random: std.Random, pkt: *GeneratedPacket) void {
    if (pkt.len < 34) return;
    const choice = random.intRangeLessThan(u8, 0, 10);
    switch (choice) {
        0 => {
            // IP total_len = 0
            pkt.buf[16] = 0;
            pkt.buf[17] = 0;
        },
        1 => {
            // IP total_len = 20 (header only, no transport)
            pkt.buf[16] = 0;
            pkt.buf[17] = 20;
        },
        2 => {
            // IP total_len = 65535 (max)
            pkt.buf[16] = 0xFF;
            pkt.buf[17] = 0xFF;
        },
        3 => {
            // IP total_len = actual - 1
            const actual: u16 = @intCast(pkt.len - 14);
            const val = actual -% 1;
            pkt.buf[16] = @truncate(val >> 8);
            pkt.buf[17] = @truncate(val);
        },
        4 => {
            // TCP data offset = 0 (no header)
            if (pkt.len > 46) pkt.buf[46] = 0x00;
        },
        5 => {
            // TCP data offset = 15 (60 bytes, probably past packet end)
            if (pkt.len > 46) pkt.buf[46] = 0xF0;
        },
        6 => {
            // UDP length = 0
            if (pkt.len > 39 and pkt.buf[23] == 17) {
                pkt.buf[38] = 0;
                pkt.buf[39] = 0;
            }
        },
        7 => {
            // UDP length = 7 (less than UDP header)
            if (pkt.len > 39 and pkt.buf[23] == 17) {
                pkt.buf[38] = 0;
                pkt.buf[39] = 7;
            }
        },
        8 => {
            // IHL = 0 (headerLen = 0)
            pkt.buf[14] = (pkt.buf[14] & 0xF0) | 0;
        },
        9 => {
            // IHL = 15 (headerLen = 60, extends into transport)
            pkt.buf[14] = (pkt.buf[14] & 0xF0) | 0x0F;
        },
        else => {},
    }
}

fn protocolConfusion(random: std.Random, pkt: *GeneratedPacket) void {
    const choice = random.intRangeLessThan(u8, 0, 7);
    switch (choice) {
        0 => {
            // IPv4 ethertype but set version to 6
            pkt.buf[14] = (6 << 4) | (pkt.buf[14] & 0x0F);
        },
        1 => {
            // Set IP protocol to 0 (reserved)
            if (pkt.len > 23) pkt.buf[23] = 0;
        },
        2 => {
            // Set IP protocol to 2 (IGMP)
            if (pkt.len > 23) pkt.buf[23] = 2;
        },
        3 => {
            // Set IP protocol to 47 (GRE)
            if (pkt.len > 23) pkt.buf[23] = 47;
        },
        4 => {
            // Set IP protocol to 255
            if (pkt.len > 23) pkt.buf[23] = 255;
        },
        5 => {
            // TCP flags: all set (SYN+FIN+RST+ACK+PSH+URG)
            if (pkt.len > 47) pkt.buf[47] = 0x3F;
        },
        6 => {
            // TCP flags: none set
            if (pkt.len > 47) pkt.buf[47] = 0x00;
        },
        else => {},
    }
}

fn addressBoundary(random: std.Random, pkt: *GeneratedPacket) void {
    if (pkt.len < 34) return;
    const ip_idx = random.intRangeLessThan(usize, 0, boundary_ips.len);
    const ip = boundary_ips[ip_idx];

    if (random.boolean()) {
        // Mutate source IP
        @memcpy(pkt.buf[26..30], &ip);
    } else {
        // Mutate dest IP
        @memcpy(pkt.buf[30..34], &ip);
    }

    // Also sometimes mutate MACs
    if (random.float(f32) < 0.3) {
        if (random.boolean()) {
            @memset(pkt.buf[0..6], 0xFF); // broadcast dest
        } else {
            @memset(pkt.buf[0..6], 0); // zero dest
        }
    }
}

fn tcpOptionsCorrupt(random: std.Random, pkt: *GeneratedPacket) void {
    if (pkt.len < 54) return;
    // Only meaningful for TCP SYN packets
    if (pkt.buf[23] != 6) return;

    const choice = random.intRangeLessThan(u8, 0, 6);
    switch (choice) {
        0 => {
            // Add MSS option with value 0, extend TCP header
            pkt.buf[46] = 0x60; // data offset = 6 (24 bytes)
            if (pkt.len >= 58) {
                pkt.buf[54] = 2; // MSS kind
                pkt.buf[55] = 4; // MSS length
                pkt.buf[56] = 0; // MSS value = 0
                pkt.buf[57] = 0;
            }
            pkt.buf[47] |= 0x02; // Ensure SYN flag
        },
        1 => {
            // MSS = 65535
            pkt.buf[46] = 0x60;
            if (pkt.len >= 58) {
                pkt.buf[54] = 2;
                pkt.buf[55] = 4;
                pkt.buf[56] = 0xFF;
                pkt.buf[57] = 0xFF;
            }
            pkt.buf[47] |= 0x02;
        },
        2 => {
            // Option kind=2 but length=0 (potential infinite loop in option walking)
            pkt.buf[46] = 0x60;
            if (pkt.len >= 58) {
                pkt.buf[54] = 2;
                pkt.buf[55] = 0; // length 0!
                pkt.buf[56] = 0;
                pkt.buf[57] = 0;
            }
            pkt.buf[47] |= 0x02;
        },
        3 => {
            // Option kind=2 but length=255 (past packet end)
            pkt.buf[46] = 0x60;
            if (pkt.len >= 58) {
                pkt.buf[54] = 2;
                pkt.buf[55] = 255;
                pkt.buf[56] = 0;
                pkt.buf[57] = 0;
            }
            pkt.buf[47] |= 0x02;
        },
        4 => {
            // TCP data offset = 15 (60-byte header) but packet is only 54 bytes
            pkt.buf[46] = 0xF0;
            pkt.buf[47] |= 0x02;
        },
        5 => {
            // MSS option with kind=2, length=3 (wrong length, should be 4)
            pkt.buf[46] = 0x60;
            if (pkt.len >= 58) {
                pkt.buf[54] = 2;
                pkt.buf[55] = 3;
                pkt.buf[56] = 0x05;
                pkt.buf[57] = 0xB4; // 1460 in the "wrong" position
            }
            pkt.buf[47] |= 0x02;
        },
        else => {},
    }
}

fn truncatePacket(random: std.Random, pkt: *GeneratedPacket) void {
    // Truncate to a boundary value
    const boundaries = [_]u32{ 0, 1, 13, 14, 15, 20, 33, 34, 35, 41, 42, 43, 53, 54 };
    const idx = random.intRangeLessThan(usize, 0, boundaries.len);
    const new_len = boundaries[idx];
    if (new_len < pkt.len) {
        pkt.len = new_len;
    }
}
