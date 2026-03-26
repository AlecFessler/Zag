const lib = @import("lib");

const syscall = lib.syscall;

pub const Protocol = enum(u8) { icmp = 1, tcp = 6, udp = 17 };
pub const Protocol6 = enum(u8) { tcp = 6, udp = 17, icmpv6 = 58 };

pub fn now() u64 {
    return @bitCast(syscall.clock_gettime());
}

pub fn logEvent(msg: []const u8) void {
    syscall.write(msg);
}

pub fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

pub fn startsWith(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return eql(haystack[0..prefix.len], prefix);
}

pub fn appendStr(buf: []u8, pos: usize, s: []const u8) usize {
    const end = @min(pos + s.len, buf.len);
    @memcpy(buf[pos..end], s[0..(end - pos)]);
    return end;
}

pub fn appendDec(buf: []u8, pos: usize, val: u64) usize {
    if (val == 0) {
        if (pos < buf.len) {
            buf[pos] = '0';
            return pos + 1;
        }
        return pos;
    }
    var tmp: [20]u8 = undefined;
    var v = val;
    var i: usize = 20;
    while (v > 0) {
        i -= 1;
        tmp[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    return appendStr(buf, pos, tmp[i..20]);
}

pub fn appendIp(buf: []u8, pos: usize, ip: [4]u8) usize {
    var p = pos;
    for (ip, 0..) |octet, idx| {
        p = appendDec(buf, p, octet);
        if (idx < 3) p = appendStr(buf, p, ".");
    }
    return p;
}

pub fn appendMac(buf: []u8, pos: usize, mac: [6]u8) usize {
    const hex_chars = "0123456789abcdef";
    var p = pos;
    for (mac, 0..) |byte, idx| {
        if (p + 2 > buf.len) break;
        buf[p] = hex_chars[byte >> 4];
        buf[p + 1] = hex_chars[byte & 0xf];
        p += 2;
        if (idx < 5) p = appendStr(buf, p, ":");
    }
    return p;
}

pub fn parseIp(s: []const u8) ?[4]u8 {
    var ip: [4]u8 = undefined;
    var octet: u16 = 0;
    var idx: usize = 0;
    var digits: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (digits == 0 or octet > 255 or idx >= 3) return null;
            ip[idx] = @truncate(octet);
            idx += 1;
            octet = 0;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            digits += 1;
        } else {
            return null;
        }
    }
    if (digits == 0 or octet > 255 or idx != 3) return null;
    ip[3] = @truncate(octet);
    return ip;
}

pub fn parsePortIpPort(s: []const u8) ?struct { port1: u16, ip: [4]u8, port2: u16 } {
    var port1: u16 = 0;
    var i: usize = 0;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
        port1 = port1 * 10 + @as(u16, s[i] - '0');
    }
    if (i == 0 or i >= s.len or s[i] != ' ') return null;
    i += 1;

    var ip_end = i;
    while (ip_end < s.len and s[ip_end] != ' ') : (ip_end += 1) {}
    const ip = parseIp(s[i..ip_end]) orelse return null;
    if (ip_end >= s.len) return null;
    i = ip_end + 1;

    var port2: u16 = 0;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
        port2 = port2 * 10 + @as(u16, s[i] - '0');
    }
    if (port2 == 0) return null;
    return .{ .port1 = port1, .ip = ip, .port2 = port2 };
}

pub fn readU16Be(buf: []const u8) u16 {
    return @as(u16, buf[0]) << 8 | buf[1];
}

pub fn writeU16Be(buf: []u8, val: u16) void {
    buf[0] = @truncate(val >> 8);
    buf[1] = @truncate(val);
}

pub fn computeChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, data[i]) << 8 | data[i + 1];
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @truncate(~sum);
}

/// Recompute TCP/UDP checksum from scratch after NAT header modification.
/// Call this AFTER src/dst IP and ports have been rewritten in the packet.
pub fn recomputeTransportChecksum(pkt: []u8, transport_start: usize, len: u32, protocol: u8) void {
    if (transport_start + 8 > len) return;
    // Use IP Total Length to determine actual transport segment length,
    // not the Ethernet frame length (which may include padding).
    const ip_total_len: u16 = readU16Be(pkt[16..18]);
    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const tcp_len: u16 = ip_total_len - ip_hdr_len;

    // Zero out the checksum field before computing
    if (protocol == 6) {
        // TCP checksum is at offset 16-17
        if (transport_start + 18 > len) return;
        pkt[transport_start + 16] = 0;
        pkt[transport_start + 17] = 0;
    } else {
        // UDP checksum is at offset 6-7
        pkt[transport_start + 6] = 0;
        pkt[transport_start + 7] = 0;
    }

    // Build pseudo-header sum: src_ip + dst_ip + protocol + tcp/udp_len
    var sum: u32 = 0;
    // Source IP (pkt[26..30])
    sum += @as(u32, pkt[26]) << 8 | pkt[27];
    sum += @as(u32, pkt[28]) << 8 | pkt[29];
    // Dest IP (pkt[30..34])
    sum += @as(u32, pkt[30]) << 8 | pkt[31];
    sum += @as(u32, pkt[32]) << 8 | pkt[33];
    // Protocol
    sum += @as(u32, protocol);
    // Transport length
    sum += @as(u32, tcp_len);

    // Sum the transport segment (use tcp_len, not frame len, to avoid padding)
    const seg_end = transport_start + tcp_len;
    var i: usize = transport_start;
    while (i + 1 < seg_end) : (i += 2) {
        sum += @as(u32, pkt[i]) << 8 | pkt[i + 1];
    }
    if (i < seg_end) sum += @as(u32, pkt[i]) << 8;

    // Fold carry
    while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    var cs: u16 = @truncate(~sum);
    if (protocol == 6 and cs == 0) cs = 0xFFFF;

    if (protocol == 6) {
        pkt[transport_start + 16] = @truncate(cs >> 8);
        pkt[transport_start + 17] = @truncate(cs);
    } else {
        pkt[transport_start + 6] = @truncate(cs >> 8);
        pkt[transport_start + 7] = @truncate(cs);
    }
}

// ── IPv6 helpers ─────────────────────────────────────────────────────────

pub fn isLinkLocal6(ip6: [16]u8) bool {
    return ip6[0] == 0xfe and ip6[1] & 0xc0 == 0x80;
}

pub fn isMulticast6(ip6: [16]u8) bool {
    return ip6[0] == 0xff;
}

pub fn isAllZeros(data: []const u8) bool {
    for (data) |b| {
        if (b != 0) return false;
    }
    return true;
}

/// Solicited-node multicast address: ff02::1:ffXX:XXXX from last 3 bytes.
pub fn solicitedNodeMulticast(ip6: [16]u8) [16]u8 {
    var addr: [16]u8 = .{0} ** 16;
    addr[0] = 0xff;
    addr[1] = 0x02;
    addr[11] = 0x01;
    addr[12] = 0xff;
    addr[13] = ip6[13];
    addr[14] = ip6[14];
    addr[15] = ip6[15];
    return addr;
}

/// Multicast MAC for an IPv6 multicast address: 33:33:XX:XX:XX:XX from last 4 bytes.
pub fn multicastMac6(ip6: [16]u8) [6]u8 {
    return .{ 0x33, 0x33, ip6[12], ip6[13], ip6[14], ip6[15] };
}

/// Derive EUI-64 link-local address from MAC.
pub fn macToLinkLocal(mac: [6]u8) [16]u8 {
    var addr: [16]u8 = .{0} ** 16;
    addr[0] = 0xfe;
    addr[1] = 0x80;
    addr[8] = mac[0] ^ 0x02;
    addr[9] = mac[1];
    addr[10] = mac[2];
    addr[11] = 0xFF;
    addr[12] = 0xFE;
    addr[13] = mac[3];
    addr[14] = mac[4];
    addr[15] = mac[5];
    return addr;
}

/// Derive global address from prefix + MAC (EUI-64 interface ID).
pub fn prefixToGlobal(prefix: [16]u8, prefix_len: u8, mac: [6]u8) [16]u8 {
    var addr = prefix;
    // Zero out host part
    const prefix_bytes = prefix_len / 8;
    if (prefix_bytes < 16) {
        @memset(addr[prefix_bytes..16], 0);
    }
    // Fill interface ID (EUI-64) in the last 8 bytes
    addr[8] = mac[0] ^ 0x02;
    addr[9] = mac[1];
    addr[10] = mac[2];
    addr[11] = 0xFF;
    addr[12] = 0xFE;
    addr[13] = mac[3];
    addr[14] = mac[4];
    addr[15] = mac[5];
    return addr;
}

/// Compute ICMPv6 checksum with IPv6 pseudo-header.
pub fn computeIcmpv6Checksum(src_ip6: [16]u8, dst_ip6: [16]u8, icmpv6_data: []const u8) u16 {
    var sum: u32 = 0;
    // Pseudo-header: src (16 bytes)
    var i: usize = 0;
    while (i + 1 < 16) : (i += 2) {
        sum += @as(u32, src_ip6[i]) << 8 | src_ip6[i + 1];
    }
    // Pseudo-header: dst (16 bytes)
    i = 0;
    while (i + 1 < 16) : (i += 2) {
        sum += @as(u32, dst_ip6[i]) << 8 | dst_ip6[i + 1];
    }
    // Pseudo-header: upper-layer length (4 bytes, big-endian)
    const ulen: u32 = @truncate(icmpv6_data.len);
    sum += ulen >> 16;
    sum += ulen & 0xFFFF;
    // Pseudo-header: next header = 58 (ICMPv6)
    sum += 58;

    // Sum the ICMPv6 data
    i = 0;
    while (i + 1 < icmpv6_data.len) : (i += 2) {
        sum += @as(u32, icmpv6_data[i]) << 8 | icmpv6_data[i + 1];
    }
    if (i < icmpv6_data.len) sum += @as(u32, icmpv6_data[i]) << 8;

    while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @truncate(~sum);
}

/// Append IPv6 address in hex colon notation (full form).
pub fn appendIp6(buf: []u8, pos: usize, ip6: [16]u8) usize {
    const hex_chars = "0123456789abcdef";
    var p = pos;
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        if (i > 0) p = appendStr(buf, p, ":");
        if (p + 4 > buf.len) break;
        buf[p] = hex_chars[ip6[i] >> 4];
        buf[p + 1] = hex_chars[ip6[i] & 0xf];
        buf[p + 2] = hex_chars[ip6[i + 1] >> 4];
        buf[p + 3] = hex_chars[ip6[i + 1] & 0xf];
        p += 4;
    }
    return p;
}
