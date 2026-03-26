const router = @import("router");

const arp = router.net.arp;
const dhcp_server = router.services.dhcp_server;
const firewall = router.ipv4.firewall;
const main = router.state;
const nat = router.ipv4.nat;
const util = router.util;

const iface_mod = router.net.iface;
const Iface = iface_mod.Iface;

pub const HTTP_PORT: u16 = 80;

// ── Message tags (must match http_server/main.zig) ──────────────────
pub const MSG_HTTP_REQUEST: u8 = 0x10;
pub const MSG_HTTP_RESPONSE: u8 = 0x11;
pub const MSG_STATE_QUERY: u8 = 0x12;
pub const MSG_STATE_RESPONSE: u8 = 0x13;

// Simple single-connection TCP state machine for HTTP/1.0
const TcpState = enum { closed, syn_received, established, fin_wait };

var state: TcpState = .closed;
var client_ip: [4]u8 = .{ 0, 0, 0, 0 };
var client_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
var client_port: u16 = 0;
var local_seq: u32 = 1;
var remote_seq: u32 = 0;
var request_buf: [2048]u8 = undefined;
var request_len: usize = 0;

/// Handle an incoming TCP packet on port 80 (LAN interface only).
/// Returns true if the packet was consumed.
pub fn handleTcp(pkt: []u8, len: u32) bool {
    if (len < 54) return false; // 14 eth + 20 IP + 20 TCP minimum

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const tcp_start: usize = 14 + ip_hdr_len;
    if (tcp_start + 20 > len) return false;

    const dst_port = util.readU16Be(pkt[tcp_start + 2 ..][0..2]);
    if (dst_port != HTTP_PORT) return false;

    const src_port = util.readU16Be(pkt[tcp_start..][0..2]);
    const flags = pkt[tcp_start + 13];
    const seq = readU32Be(pkt[tcp_start + 4 ..][0..4]);
    const tcp_data_offset: usize = (@as(usize, pkt[tcp_start + 12] >> 4)) * 4;
    const payload_start = tcp_start + tcp_data_offset;
    // Use IP total length to exclude Ethernet padding (min frame = 60 bytes)
    const ip_total_len: usize = util.readU16Be(pkt[16..18]);
    const actual_end: usize = @min(14 + ip_total_len, len);
    const payload_len: usize = if (payload_start < actual_end) actual_end - payload_start else 0;

    const is_syn = flags & 0x02 != 0;
    const is_ack = flags & 0x10 != 0;
    const is_fin = flags & 0x01 != 0;
    const is_rst = flags & 0x04 != 0;

    if (is_rst) {
        if (state != .closed and src_port == client_port) {
            state = .closed;
            request_len = 0;
        }
        return true;
    }

    if (is_syn and !is_ack) {
        // New connection — SYN
        @memcpy(&client_ip, pkt[26..30]);
        @memcpy(&client_mac, pkt[6..12]);
        client_port = src_port;
        remote_seq = seq + 1;
        local_seq = 0x5A470000 +% @as(u32, @truncate(util.now() & 0xFFFF));
        request_len = 0;
        state = .syn_received;

        // Send SYN-ACK
        sendTcpPacket(&.{}, 0x12, local_seq, remote_seq); // SYN+ACK
        local_seq += 1;
        return true;
    }

    if (state == .closed) return false;
    if (src_port != client_port) return false;

    if (state == .syn_received and is_ack) {
        state = .established;
    }

    if (state == .established and payload_len > 0) {
        // Accumulate request data
        const copy_len = @min(payload_len, request_buf.len - request_len);
        @memcpy(request_buf[request_len..][0..copy_len], pkt[payload_start..][0..copy_len]);
        request_len += copy_len;
        remote_seq = seq + @as(u32, @intCast(payload_len));

        // Check if we have a complete HTTP request (ends with \r\n\r\n)
        if (hasCompleteRequest()) {
            // Don't send a separate ACK — the response packet will ACK the data.
            // (txSendLocal has a single pending slot; sending ACK + response
            //  back-to-back would drop the response.)
            handleHttpRequest();
        } else {
            // Not complete yet — ACK the data to let client continue sending
            sendTcpPacket(&.{}, 0x10, local_seq, remote_seq);
        }
    }

    if (is_fin) {
        remote_seq += 1;
        // ACK the FIN and send our own FIN
        sendTcpPacket(&.{}, 0x11, local_seq, remote_seq); // FIN+ACK
        local_seq += 1;
        state = .closed;
        request_len = 0;
    }

    return true;
}

fn hasCompleteRequest() bool {
    if (request_len < 4) return false;
    var i: usize = 0;
    while (i + 3 < request_len) : (i += 1) {
        if (request_buf[i] == '\r' and request_buf[i + 1] == '\n' and
            request_buf[i + 2] == '\r' and request_buf[i + 3] == '\n')
            return true;
    }
    return false;
}

fn handleHttpRequest() void {
    // Parse GET request and extract path
    if (request_len < 14) return; // "GET / HTTP/1.0"
    if (!util.startsWith(request_buf[0..@min(request_len, 4)], "GET ")) {
        directResponse("405 Method Not Allowed", "text/plain", "Method Not Allowed");
        return;
    }

    // Find path end
    var path_end: usize = 4;
    while (path_end < request_len and request_buf[path_end] != ' ' and request_buf[path_end] != '\r') : (path_end += 1) {}
    const path = request_buf[4..path_end];

    if (util.eql(path, "/") or util.eql(path, "/index.html")) {
        directResponse("200 OK", "text/html", "<h1>Zag RouterOS</h1>");
    } else if (util.eql(path, "/api/status")) {
        var buf: [512]u8 = undefined;
        const n = formatJsonStatus(&buf);
        directResponse("200 OK", "application/json", buf[0..n]);
    } else if (util.eql(path, "/api/ifstat")) {
        var buf: [512]u8 = undefined;
        const n = formatJsonIfstat(&buf);
        directResponse("200 OK", "application/json", buf[0..n]);
    } else if (util.eql(path, "/api/arp")) {
        var buf: [2048]u8 = undefined;
        const n = formatJsonArp(&buf);
        directResponse("200 OK", "application/json", buf[0..n]);
    } else if (util.eql(path, "/api/nat")) {
        var buf: [4096]u8 = undefined;
        const n = formatJsonNat(&buf);
        directResponse("200 OK", "application/json", buf[0..n]);
    } else if (util.eql(path, "/api/leases")) {
        var buf: [2048]u8 = undefined;
        const n = formatJsonLeases(&buf);
        directResponse("200 OK", "application/json", buf[0..n]);
    } else if (util.eql(path, "/api/rules")) {
        var buf: [2048]u8 = undefined;
        const n = formatJsonRules(&buf);
        directResponse("200 OK", "application/json", buf[0..n]);
    } else {
        directResponse("404 Not Found", "text/plain", "Not Found");
    }
}

fn directResponse(status_val: []const u8, content_type: []const u8, body: []const u8) void {
    var hdr: [256]u8 = undefined;
    var hp: usize = 0;
    hp = util.appendStr(&hdr, hp, "HTTP/1.0 ");
    hp = util.appendStr(&hdr, hp, status_val);
    hp = util.appendStr(&hdr, hp, "\r\nContent-Type: ");
    hp = util.appendStr(&hdr, hp, content_type);
    hp = util.appendStr(&hdr, hp, "\r\nContent-Length: ");
    hp = util.appendDec(&hdr, hp, body.len);
    hp = util.appendStr(&hdr, hp, "\r\nConnection: close\r\n\r\n");
    sendTcpData(hdr[0..hp], body);
}

fn sendTcpData(header: []const u8, body: []const u8) void {
    // Send in MSS-sized chunks (1460 max per segment, but keep it smaller for safety)
    const MSS: usize = 1400;
    var offset: usize = 0;
    const total_len = header.len + body.len;

    while (offset < total_len) {
        var seg: [1500]u8 = undefined;
        var seg_len: usize = 0;

        while (seg_len < MSS and offset + seg_len < total_len) {
            const pos = offset + seg_len;
            if (pos < header.len) {
                seg[seg_len] = header[pos];
            } else {
                seg[seg_len] = body[pos - header.len];
            }
            seg_len += 1;
        }

        const is_last = (offset + seg_len >= total_len);
        const flags: u8 = if (is_last) 0x19 else 0x18; // FIN+PSH+ACK or PSH+ACK
        sendTcpPacket(seg[0..seg_len], flags, local_seq, remote_seq);
        local_seq +%= @intCast(seg_len);
        if (is_last) {
            local_seq +%= 1; // FIN consumes a sequence number
            state = .fin_wait;
        }
        offset += seg_len;
    }
}

fn sendTcpPacket(payload: []const u8, flags: u8, seq: u32, ack: u32) void {
    const ifc = &main.lan_iface;
    const tcp_hdr_len: u16 = 20;
    const ip_total: u16 = 20 + tcp_hdr_len + @as(u16, @intCast(payload.len));
    const frame_len: usize = @max(@as(usize, 14 + ip_total), 60);

    var pkt: [1600]u8 = undefined;
    @memset(pkt[0..frame_len], 0);

    // Ethernet
    @memcpy(pkt[0..6], &client_mac);
    @memcpy(pkt[6..12], &ifc.mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IP header
    pkt[14] = 0x45;
    util.writeU16Be(pkt[16..18], ip_total);
    pkt[20] = 0x40; // Don't Fragment
    pkt[22] = 64; // TTL
    pkt[23] = 6; // TCP
    @memcpy(pkt[26..30], &ifc.ip);
    @memcpy(pkt[30..34], &client_ip);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = util.computeChecksum(pkt[14..34]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    // TCP header
    const tcp_start: usize = 34;
    util.writeU16Be(pkt[tcp_start..][0..2], HTTP_PORT); // src port
    util.writeU16Be(pkt[tcp_start + 2 ..][0..2], client_port); // dst port
    writeU32Be(pkt[tcp_start + 4 ..][0..4], seq);
    writeU32Be(pkt[tcp_start + 8 ..][0..4], ack);
    pkt[tcp_start + 12] = 0x50; // data offset = 5 (20 bytes)
    pkt[tcp_start + 13] = flags;
    util.writeU16Be(pkt[tcp_start + 14 ..][0..2], 65535); // window size

    // Copy payload
    if (payload.len > 0) {
        @memcpy(pkt[tcp_start + 20 ..][0..payload.len], payload);
    }

    // TCP checksum
    util.recomputeTransportChecksum(&pkt, tcp_start, @intCast(14 + ip_total), 6);

    _ = ifc.txSendLocal(pkt[0..@max(frame_len, 14 + @as(usize, ip_total))]);
}

fn readU32Be(buf: []const u8) u32 {
    return @as(u32, buf[0]) << 24 | @as(u32, buf[1]) << 16 | @as(u32, buf[2]) << 8 | buf[3];
}

fn writeU32Be(buf: []u8, val: u32) void {
    buf[0] = @truncate(val >> 24);
    buf[1] = @truncate(val >> 16);
    buf[2] = @truncate(val >> 8);
    buf[3] = @truncate(val);
}

// ── JSON state formatters (called from service thread) ───────────────
// These write JSON to the provided buffer and return the number of bytes written.

pub fn formatJsonStatus(buf: []u8) usize {
    var p: usize = 0;
    p = util.appendStr(buf, p, "{\"wan\":{\"ip\":\"");
    p = util.appendIp(buf, p, main.wan_iface.ip);
    p = util.appendStr(buf, p, "\",\"mac\":\"");
    p = util.appendMac(buf, p, main.wan_iface.mac);
    p = util.appendStr(buf, p, "\",\"gateway\":\"");
    p = util.appendIp(buf, p, main.wan_gateway);
    p = util.appendStr(buf, p, "\"}");
    if (main.has_lan) {
        p = util.appendStr(buf, p, ",\"lan\":{\"ip\":\"");
        p = util.appendIp(buf, p, main.lan_iface.ip);
        p = util.appendStr(buf, p, "\",\"mac\":\"");
        p = util.appendMac(buf, p, main.lan_iface.mac);
        p = util.appendStr(buf, p, "\"}");
    }
    p = util.appendStr(buf, p, "}");
    return p;
}

pub fn formatJsonIfstat(buf: []u8) usize {
    var p: usize = 0;
    p = util.appendStr(buf, p, "{\"wan\":{\"rx\":");
    p = util.appendDec(buf, p, main.wan_iface.stats.rx_packets);
    p = util.appendStr(buf, p, ",\"tx\":");
    p = util.appendDec(buf, p, main.wan_iface.stats.tx_packets);
    p = util.appendStr(buf, p, ",\"drop\":");
    p = util.appendDec(buf, p, main.wan_iface.stats.rx_dropped);
    p = util.appendStr(buf, p, "}");
    if (main.has_lan) {
        p = util.appendStr(buf, p, ",\"lan\":{\"rx\":");
        p = util.appendDec(buf, p, main.lan_iface.stats.rx_packets);
        p = util.appendStr(buf, p, ",\"tx\":");
        p = util.appendDec(buf, p, main.lan_iface.stats.tx_packets);
        p = util.appendStr(buf, p, ",\"drop\":");
        p = util.appendDec(buf, p, main.lan_iface.stats.rx_dropped);
        p = util.appendStr(buf, p, "}");
    }
    p = util.appendStr(buf, p, "}");
    return p;
}

pub fn formatJsonArp(buf: []u8) usize {
    var p: usize = 0;
    p = util.appendStr(buf, p, "[");
    var first = true;
    for (&main.wan_iface.arp_table) |*e| {
        if (!e.valid) continue;
        if (!first) p = util.appendStr(buf, p, ",");
        p = util.appendStr(buf, p, "{\"iface\":\"WAN\",\"ip\":\"");
        p = util.appendIp(buf, p, e.ip);
        p = util.appendStr(buf, p, "\",\"mac\":\"");
        p = util.appendMac(buf, p, e.mac);
        p = util.appendStr(buf, p, "\"}");
        first = false;
    }
    if (main.has_lan) {
        for (&main.lan_iface.arp_table) |*e| {
            if (!e.valid) continue;
            if (!first) p = util.appendStr(buf, p, ",");
            p = util.appendStr(buf, p, "{\"iface\":\"LAN\",\"ip\":\"");
            p = util.appendIp(buf, p, e.ip);
            p = util.appendStr(buf, p, "\",\"mac\":\"");
            p = util.appendMac(buf, p, e.mac);
            p = util.appendStr(buf, p, "\"}");
            first = false;
        }
    }
    p = util.appendStr(buf, p, "]");
    return p;
}

pub fn formatJsonNat(buf: []u8) usize {
    var p: usize = 0;
    p = util.appendStr(buf, p, "[");
    var first = true;
    for (&main.nat_table) |*e| {
        if (@atomicLoad(u8, &e.state, .acquire) != 1) continue;
        if (!first) p = util.appendStr(buf, p, ",");
        p = util.appendStr(buf, p, "{\"proto\":\"");
        const proto_str: []const u8 = if (e.protocol == 6) "tcp" else if (e.protocol == 17) "udp" else "icmp";
        p = util.appendStr(buf, p, proto_str);
        p = util.appendStr(buf, p, "\",\"lan_ip\":\"");
        p = util.appendIp(buf, p, e.lan_ip);
        p = util.appendStr(buf, p, "\",\"lan_port\":");
        p = util.appendDec(buf, p, e.lan_port);
        p = util.appendStr(buf, p, ",\"wan_port\":");
        p = util.appendDec(buf, p, e.wan_port);
        p = util.appendStr(buf, p, ",\"dst_ip\":\"");
        p = util.appendIp(buf, p, e.dst_ip);
        p = util.appendStr(buf, p, "\",\"dst_port\":");
        p = util.appendDec(buf, p, e.dst_port);
        p = util.appendStr(buf, p, "}");
        first = false;
    }
    p = util.appendStr(buf, p, "]");
    return p;
}

pub fn formatJsonLeases(buf: []u8) usize {
    var p: usize = 0;
    p = util.appendStr(buf, p, "[");
    var first = true;
    for (&main.dhcp_leases) |*l| {
        if (!l.valid) continue;
        if (!first) p = util.appendStr(buf, p, ",");
        p = util.appendStr(buf, p, "{\"ip\":\"");
        p = util.appendIp(buf, p, l.ip);
        p = util.appendStr(buf, p, "\",\"mac\":\"");
        p = util.appendMac(buf, p, l.mac);
        p = util.appendStr(buf, p, "\"}");
        first = false;
    }
    p = util.appendStr(buf, p, "]");
    return p;
}

pub fn formatJsonRules(buf: []u8) usize {
    var p: usize = 0;
    p = util.appendStr(buf, p, "{\"firewall\":[");
    var first = true;
    for (&main.firewall_rules) |*r| {
        if (!r.valid) continue;
        if (!first) p = util.appendStr(buf, p, ",");
        p = util.appendStr(buf, p, "{\"action\":\"");
        p = util.appendStr(buf, p, if (r.action == .block) "block" else "allow");
        p = util.appendStr(buf, p, "\",\"ip\":\"");
        p = util.appendIp(buf, p, r.src_ip);
        p = util.appendStr(buf, p, "\"}");
        first = false;
    }
    p = util.appendStr(buf, p, "],\"forwards\":[");
    first = true;
    for (&main.port_forwards) |*f| {
        if (!f.valid) continue;
        if (!first) p = util.appendStr(buf, p, ",");
        p = util.appendStr(buf, p, "{\"proto\":\"");
        p = util.appendStr(buf, p, if (f.protocol == .tcp) "tcp" else "udp");
        p = util.appendStr(buf, p, "\",\"wan_port\":");
        p = util.appendDec(buf, p, f.wan_port);
        p = util.appendStr(buf, p, ",\"lan_ip\":\"");
        p = util.appendIp(buf, p, f.lan_ip);
        p = util.appendStr(buf, p, "\",\"lan_port\":");
        p = util.appendDec(buf, p, f.lan_port);
        p = util.appendStr(buf, p, "}");
        first = false;
    }
    p = util.appendStr(buf, p, "]}");
    return p;
}
