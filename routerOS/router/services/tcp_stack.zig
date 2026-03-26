const router = @import("router");

const h = router.net.headers;
const main = router.state;
const util = router.util;

pub const HTTP_PORT: u16 = 80;

// ── Message tags (must match http_server/main.zig) ──────────────────
pub const MSG_HTTP_REQUEST: u8 = 0x10;
pub const MSG_HTTP_RESPONSE: u8 = 0x11;
pub const MSG_STATE_QUERY: u8 = 0x12;
pub const MSG_STATE_RESPONSE: u8 = 0x13;
pub const MSG_MUTATION_REQUEST: u8 = 0x14;
pub const MSG_MUTATION_RESPONSE: u8 = 0x15;

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
    var i: usize = 0;
    while (i + 3 < request_len) : (i += 1) {
        if (request_buf[i] == '\r' and request_buf[i + 1] == '\n' and
            request_buf[i + 2] == '\r' and request_buf[i + 3] == '\n')
            return true;
    }
    return false;
}

/// Forward the complete HTTP request to the http_server process via IPC.
fn forwardToHttpServer() void {
    const chan = &(main.http_chan orelse return);
    var msg: [2049]u8 = undefined;
    msg[0] = MSG_HTTP_REQUEST;
    const len = @min(request_len, msg.len - 1);
    @memcpy(msg[1..][0..len], request_buf[0..len]);
    _ = chan.send(msg[0 .. 1 + len]);
    request_len = 0;
}

/// Send an HTTP response as TCP data. Called by router/main.zig when
/// MSG_HTTP_RESPONSE is received back from the http_server process.
pub fn sendHttpResponse(header: []const u8, body: []const u8) void {
    sendTcpData(header, body);
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
    p = util.appendStr(buf, p, "\"}");
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
