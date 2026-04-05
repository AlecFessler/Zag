const lib = @import("lib");
const router = @import("router");

const h = router.hal.headers;
const http_proto = lib.http;
const main = router.state;
const util = router.util;

const HttpServer = http_proto.Server;

pub const HTTP_PORT: u16 = 80;

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

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return false;
    const ip_hdr_len = ip.headerLen();
    const tcp_start: usize = 14 + ip_hdr_len;
    if (tcp_start + 20 > len) return false;

    const tcp = h.TcpHeader.parseMut(pkt[tcp_start..]) orelse return false;
    if (tcp.dstPort() != HTTP_PORT) return false;

    const src_port = tcp.srcPort();
    const seq = tcp.seq();
    const tcp_data_offset: usize = tcp.dataOffset();
    const payload_start = tcp_start + tcp_data_offset;
    // Use IP total length to exclude Ethernet padding (min frame = 60 bytes)
    const ip_total_len: usize = ip.totalLen();
    const actual_end: usize = @min(14 + ip_total_len, len);
    const payload_len: usize = if (payload_start < actual_end) actual_end - payload_start else 0;

    const is_syn = tcp.isSyn();
    const is_ack = tcp.isAck();
    const is_fin = tcp.isFin();
    const is_rst = tcp.isRst();

    if (is_rst) {
        if (state != .closed and src_port == client_port) {
            state = .closed;
            request_len = 0;
        }
        return true;
    }

    if (is_syn and !is_ack) {
        // New connection — SYN
        @memcpy(&client_ip, &ip.src_ip);
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
            forwardToHttpServer();
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
    // Find \r\n\r\n (end of headers)
    var header_end: usize = 0;
    const found = while (header_end + 3 < request_len) : (header_end += 1) {
        if (request_buf[header_end] == '\r' and request_buf[header_end + 1] == '\n' and
            request_buf[header_end + 2] == '\r' and request_buf[header_end + 3] == '\n')
            break true;
    } else false;
    if (!found) return false;

    const body_start = header_end + 4;

    // For non-POST requests, headers alone are sufficient
    if (request_buf[0] != 'P' or request_buf[1] != 'O' or
        request_buf[2] != 'S' or request_buf[3] != 'T')
        return true;

    // POST: need Content-Length header to know when body is complete
    const content_length = parseContentLength(request_buf[0..header_end]) orelse return true;
    return request_len >= body_start + content_length;
}

fn parseContentLength(headers: []const u8) ?usize {
    const needle = "content-length:";
    if (headers.len < needle.len) return null;
    var i: usize = 0;
    outer: while (i + needle.len <= headers.len) : (i += 1) {
        for (needle, 0..) |nc, k| {
            const hc = headers[i + k];
            // Case-insensitive compare
            const lc = if (hc >= 'A' and hc <= 'Z') hc + 32 else hc;
            if (lc != nc) continue :outer;
        }
        // Found — skip whitespace, parse digits
        var j = i + needle.len;
        while (j < headers.len and headers[j] == ' ') : (j += 1) {}
        var val: usize = 0;
        var digits: usize = 0;
        while (j < headers.len and headers[j] >= '0' and headers[j] <= '9') : (j += 1) {
            val = val * 10 + @as(usize, headers[j] - '0');
            digits += 1;
        }
        if (digits > 0) return val;
        return null;
    }
    return null;
}

/// Forward the complete HTTP request to the http_server process via IPC.
fn forwardToHttpServer() void {
    const chan = main.http_chan orelse return;
    const srv = HttpServer.init(chan);
    srv.sendHttpRequest(request_buf[0..request_len]);
    request_len = 0;
}

/// Send an HTTP response as TCP data. Called by router/main.zig when
/// CMD_HTTP_RESPONSE is received back from the http_server process.
pub fn sendHttpResponse(header: []const u8, body: []const u8) void {
    sendTcpData(header, body);
}

/// Send a chunk of TCP data without FIN (for streaming responses).
pub fn sendTcpChunk(data: []const u8) void {
    const MSS: usize = 1400;
    var offset: usize = 0;
    while (offset < data.len) {
        const seg_len = @min(MSS, data.len - offset);
        sendTcpPacket(data[offset..][0..seg_len], 0x18, local_seq, remote_seq); // PSH+ACK
        local_seq +%= @intCast(seg_len);
        offset += seg_len;
    }
}

/// Send TCP FIN to close the connection (after streaming is complete).
pub fn sendTcpFin() void {
    sendTcpPacket(&.{}, 0x11, local_seq, remote_seq); // FIN+ACK
    local_seq +%= 1;
    state = .fin_wait;
}

// ── TCP transmission ────────────────────────────────────────────────

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
    const eth = h.EthernetHeader.parseMut(&pkt) orelse unreachable;
    @memcpy(&eth.dst_mac, &client_mac);
    @memcpy(&eth.src_mac, &ifc.mac);
    eth.setEtherType(h.EthernetHeader.IPv4);

    // IP header
    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse unreachable;
    ip.ver_ihl = 0x45;
    ip.setTotalLen(ip_total);
    pkt[20] = 0x40; // Don't Fragment
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_TCP;
    @memcpy(&ip.src_ip, &ifc.ip);
    @memcpy(&ip.dst_ip, &client_ip);

    ip.computeAndSetChecksum(&pkt);

    // TCP header
    const tcp_start: usize = 34;
    const tcp = h.TcpHeader.parseMut(pkt[tcp_start..]) orelse unreachable;
    tcp.setSrcPort(HTTP_PORT);
    tcp.setDstPort(client_port);
    tcp.setSeq(seq);
    tcp.setAck(ack);
    tcp.data_off_rsvd = 0x50;
    tcp.flags = flags;
    tcp.setWindow(65535);

    // Copy payload
    if (payload.len > 0) {
        @memcpy(pkt[tcp_start + 20 ..][0..payload.len], payload);
    }

    // TCP checksum
    util.recomputeTransportChecksum(&pkt, tcp_start, @intCast(14 + ip_total), 6);

    _ = ifc.txSendDirect(pkt[0..@max(frame_len, 14 + @as(usize, ip_total))]);
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
    p = util.appendStr(buf, p, ",\"dns\":\"");
    p = util.appendIp(buf, p, main.upstream_dns);
    p = util.appendStr(buf, p, "\",\"tz_offset\":");
    p = util.appendSignedDec(buf, p, main.tz_offset_minutes);
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
        const gen = l.seq.readBegin();
        const valid = l.valid;
        const l_ip = l.ip;
        const l_mac = l.mac;
        if (l.seq.readRetry(gen)) continue;
        if (!valid) continue;
        if (!first) p = util.appendStr(buf, p, ",");
        p = util.appendStr(buf, p, "{\"ip\":\"");
        p = util.appendIp(buf, p, l_ip);
        p = util.appendStr(buf, p, "\",\"mac\":\"");
        p = util.appendMac(buf, p, l_mac);
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
