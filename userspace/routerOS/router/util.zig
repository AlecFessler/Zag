const lib = @import("lib");

const syscall = lib.syscall;

pub const Protocol = enum(u8) { icmp = 1, tcp = 6, udp = 17 };

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

pub fn tcpChecksumAdjust(pkt: []u8, transport_start: usize, len: u32, old_ip: [4]u8, new_ip: [4]u8, old_port: u16, new_port: u16) void {
    if (transport_start + 18 > len) return;
    var sum: i32 = @as(i32, @as(u16, pkt[transport_start + 16])) << 8 | pkt[transport_start + 17];
    sum = ~sum & 0xFFFF;

    sum -= @as(i32, @as(u16, old_ip[0])) << 8 | old_ip[1];
    sum -= @as(i32, @as(u16, old_ip[2])) << 8 | old_ip[3];
    sum -= @as(i32, old_port);
    sum += @as(i32, @as(u16, new_ip[0])) << 8 | new_ip[1];
    sum += @as(i32, @as(u16, new_ip[2])) << 8 | new_ip[3];
    sum += @as(i32, new_port);

    while (sum < 0) sum += 0x10000;
    while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum & 0xFFFF;
    if (sum == 0) sum = 0xFFFF;

    pkt[transport_start + 16] = @truncate(@as(u32, @intCast(sum)) >> 8);
    pkt[transport_start + 17] = @truncate(@as(u32, @intCast(sum)));
}
