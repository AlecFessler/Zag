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

    const src_port = util.readU16Be(pkt[tcp_start ..][0..2]);
    const flags = pkt[tcp_start + 13];
    const seq = readU32Be(pkt[tcp_start + 4 ..][0..4]);
    const tcp_data_offset: usize = (@as(usize, pkt[tcp_start + 12] >> 4)) * 4;
    const payload_start = tcp_start + tcp_data_offset;
    const payload_len: usize = if (payload_start < len) len - payload_start else 0;

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

        // ACK the data
        sendTcpPacket(&.{}, 0x10, local_seq, remote_seq); // ACK

        // Check if we have a complete HTTP request (ends with \r\n\r\n)
        if (hasCompleteRequest()) {
            handleHttpRequest();
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
    // Parse GET path
    if (request_len < 14) return; // "GET / HTTP/1.0"
    if (!util.startsWith(request_buf[0..@min(request_len, 4)], "GET ")) {
        sendHttpResponse("405 Method Not Allowed", "text/plain", "Method Not Allowed");
        return;
    }

    // Find path end
    var path_end: usize = 4;
    while (path_end < request_len and request_buf[path_end] != ' ' and request_buf[path_end] != '\r') : (path_end += 1) {}
    const path = request_buf[4..path_end];

    if (util.eql(path, "/") or util.eql(path, "/index.html")) {
        sendHttpResponse("200 OK", "text/html", HTML_PAGE);
    } else if (util.eql(path, "/api/status")) {
        sendJsonStatus();
    } else if (util.eql(path, "/api/arp")) {
        sendJsonArp();
    } else if (util.eql(path, "/api/nat")) {
        sendJsonNat();
    } else if (util.eql(path, "/api/leases")) {
        sendJsonLeases();
    } else if (util.eql(path, "/api/rules")) {
        sendJsonRules();
    } else if (util.eql(path, "/api/ifstat")) {
        sendJsonIfstat();
    } else {
        sendHttpResponse("404 Not Found", "text/plain", "Not Found");
    }
}

fn sendHttpResponse(status: []const u8, content_type: []const u8, body: []const u8) void {
    // Build response in chunks since body can be large
    var hdr: [256]u8 = undefined;
    var hp: usize = 0;
    hp = util.appendStr(&hdr, hp, "HTTP/1.0 ");
    hp = util.appendStr(&hdr, hp, status);
    hp = util.appendStr(&hdr, hp, "\r\nContent-Type: ");
    hp = util.appendStr(&hdr, hp, content_type);
    hp = util.appendStr(&hdr, hp, "\r\nContent-Length: ");
    hp = util.appendDec(&hdr, hp, body.len);
    hp = util.appendStr(&hdr, hp, "\r\nConnection: close\r\n\r\n");

    // Send header + body as TCP data, then FIN
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
    util.writeU16Be(pkt[tcp_start ..][0..2], HTTP_PORT); // src port
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

// ── JSON API ────────────────────────────────────────────────────────────

fn sendJsonStatus() void {
    var body: [512]u8 = undefined;
    var p: usize = 0;
    p = util.appendStr(&body, p, "{\"wan\":{\"ip\":\"");
    p = util.appendIp(&body, p, main.wan_iface.ip);
    p = util.appendStr(&body, p, "\",\"mac\":\"");
    p = util.appendMac(&body, p, main.wan_iface.mac);
    p = util.appendStr(&body, p, "\",\"gateway\":\"");
    p = util.appendIp(&body, p, main.wan_gateway);
    p = util.appendStr(&body, p, "\"}");
    if (main.has_lan) {
        p = util.appendStr(&body, p, ",\"lan\":{\"ip\":\"");
        p = util.appendIp(&body, p, main.lan_iface.ip);
        p = util.appendStr(&body, p, "\",\"mac\":\"");
        p = util.appendMac(&body, p, main.lan_iface.mac);
        p = util.appendStr(&body, p, "\"}");
    }
    p = util.appendStr(&body, p, "}");
    sendHttpResponse("200 OK", "application/json", body[0..p]);
}

fn sendJsonIfstat() void {
    var body: [512]u8 = undefined;
    var p: usize = 0;
    p = util.appendStr(&body, p, "{\"wan\":{\"rx\":");
    p = util.appendDec(&body, p, main.wan_iface.stats.rx_packets);
    p = util.appendStr(&body, p, ",\"tx\":");
    p = util.appendDec(&body, p, main.wan_iface.stats.tx_packets);
    p = util.appendStr(&body, p, ",\"drop\":");
    p = util.appendDec(&body, p, main.wan_iface.stats.rx_dropped);
    p = util.appendStr(&body, p, "}");
    if (main.has_lan) {
        p = util.appendStr(&body, p, ",\"lan\":{\"rx\":");
        p = util.appendDec(&body, p, main.lan_iface.stats.rx_packets);
        p = util.appendStr(&body, p, ",\"tx\":");
        p = util.appendDec(&body, p, main.lan_iface.stats.tx_packets);
        p = util.appendStr(&body, p, ",\"drop\":");
        p = util.appendDec(&body, p, main.lan_iface.stats.rx_dropped);
        p = util.appendStr(&body, p, "}");
    }
    p = util.appendStr(&body, p, "}");
    sendHttpResponse("200 OK", "application/json", body[0..p]);
}

fn sendJsonArp() void {
    var body: [2048]u8 = undefined;
    var p: usize = 0;
    p = util.appendStr(&body, p, "[");
    var first = true;
    for (&main.wan_iface.arp_table) |*e| {
        if (!e.valid) continue;
        if (!first) p = util.appendStr(&body, p, ",");
        p = util.appendStr(&body, p, "{\"iface\":\"WAN\",\"ip\":\"");
        p = util.appendIp(&body, p, e.ip);
        p = util.appendStr(&body, p, "\",\"mac\":\"");
        p = util.appendMac(&body, p, e.mac);
        p = util.appendStr(&body, p, "\"}");
        first = false;
    }
    if (main.has_lan) {
        for (&main.lan_iface.arp_table) |*e| {
            if (!e.valid) continue;
            if (!first) p = util.appendStr(&body, p, ",");
            p = util.appendStr(&body, p, "{\"iface\":\"LAN\",\"ip\":\"");
            p = util.appendIp(&body, p, e.ip);
            p = util.appendStr(&body, p, "\",\"mac\":\"");
            p = util.appendMac(&body, p, e.mac);
            p = util.appendStr(&body, p, "\"}");
            first = false;
        }
    }
    p = util.appendStr(&body, p, "]");
    sendHttpResponse("200 OK", "application/json", body[0..p]);
}

fn sendJsonNat() void {
    var body: [4096]u8 = undefined;
    var p: usize = 0;
    p = util.appendStr(&body, p, "[");
    var first = true;
    for (&main.nat_table) |*e| {
        if (@atomicLoad(u8, &e.state, .acquire) != 1) continue;
        if (!first) p = util.appendStr(&body, p, ",");
        p = util.appendStr(&body, p, "{\"proto\":\"");
        const proto_str: []const u8 = if (e.protocol == 6) "tcp" else if (e.protocol == 17) "udp" else "icmp";
        p = util.appendStr(&body, p, proto_str);
        p = util.appendStr(&body, p, "\",\"lan_ip\":\"");
        p = util.appendIp(&body, p, e.lan_ip);
        p = util.appendStr(&body, p, "\",\"lan_port\":");
        p = util.appendDec(&body, p, e.lan_port);
        p = util.appendStr(&body, p, ",\"wan_port\":");
        p = util.appendDec(&body, p, e.wan_port);
        p = util.appendStr(&body, p, ",\"dst_ip\":\"");
        p = util.appendIp(&body, p, e.dst_ip);
        p = util.appendStr(&body, p, "\",\"dst_port\":");
        p = util.appendDec(&body, p, e.dst_port);
        p = util.appendStr(&body, p, "}");
        first = false;
    }
    p = util.appendStr(&body, p, "]");
    sendHttpResponse("200 OK", "application/json", body[0..p]);
}

fn sendJsonLeases() void {
    var body: [2048]u8 = undefined;
    var p: usize = 0;
    p = util.appendStr(&body, p, "[");
    var first = true;
    for (&main.dhcp_leases) |*l| {
        if (!l.valid) continue;
        if (!first) p = util.appendStr(&body, p, ",");
        p = util.appendStr(&body, p, "{\"ip\":\"");
        p = util.appendIp(&body, p, l.ip);
        p = util.appendStr(&body, p, "\",\"mac\":\"");
        p = util.appendMac(&body, p, l.mac);
        p = util.appendStr(&body, p, "\"}");
        first = false;
    }
    p = util.appendStr(&body, p, "]");
    sendHttpResponse("200 OK", "application/json", body[0..p]);
}

fn sendJsonRules() void {
    var body: [2048]u8 = undefined;
    var p: usize = 0;
    p = util.appendStr(&body, p, "{\"firewall\":[");
    var first = true;
    for (&main.firewall_rules) |*r| {
        if (!r.valid) continue;
        if (!first) p = util.appendStr(&body, p, ",");
        p = util.appendStr(&body, p, "{\"action\":\"");
        p = util.appendStr(&body, p, if (r.action == .block) "block" else "allow");
        p = util.appendStr(&body, p, "\",\"ip\":\"");
        p = util.appendIp(&body, p, r.src_ip);
        p = util.appendStr(&body, p, "\"}");
        first = false;
    }
    p = util.appendStr(&body, p, "],\"forwards\":[");
    first = true;
    for (&main.port_forwards) |*f| {
        if (!f.valid) continue;
        if (!first) p = util.appendStr(&body, p, ",");
        p = util.appendStr(&body, p, "{\"proto\":\"");
        p = util.appendStr(&body, p, if (f.protocol == .tcp) "tcp" else "udp");
        p = util.appendStr(&body, p, "\",\"wan_port\":");
        p = util.appendDec(&body, p, f.wan_port);
        p = util.appendStr(&body, p, ",\"lan_ip\":\"");
        p = util.appendIp(&body, p, f.lan_ip);
        p = util.appendStr(&body, p, "\",\"lan_port\":");
        p = util.appendDec(&body, p, f.lan_port);
        p = util.appendStr(&body, p, "}");
        first = false;
    }
    p = util.appendStr(&body, p, "]}");
    sendHttpResponse("200 OK", "application/json", body[0..p]);
}

// ── Embedded HTML Page ──────────────────────────────────────────────────

const HTML_PAGE =
    \\<!DOCTYPE html>
    \\<html><head><meta charset="utf-8"><title>Zag RouterOS</title>
    \\<style>
    \\*{margin:0;padding:0;box-sizing:border-box}
    \\body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}
    \\h1{color:#0f0;margin-bottom:20px;font-size:1.4em}
    \\h2{color:#0af;margin:15px 0 8px;font-size:1.1em}
    \\.card{background:#16213e;border:1px solid #0a3d62;border-radius:6px;padding:12px;margin-bottom:12px}
    \\table{width:100%;border-collapse:collapse;font-size:0.9em}
    \\th{text-align:left;color:#0af;padding:4px 8px;border-bottom:1px solid #0a3d62}
    \\td{padding:4px 8px}
    \\tr:hover{background:#1a1a4e}
    \\.stat{display:inline-block;margin-right:20px}
    \\.label{color:#888}.val{color:#0f0}
    \\#err{color:#f44;margin:10px 0}
    \\</style></head><body>
    \\<h1>&gt; Zag RouterOS Management</h1>
    \\<div id="err"></div>
    \\<div class="card" id="status"><h2>Interfaces</h2><div id="status-body">Loading...</div></div>
    \\<div class="card" id="stats"><h2>Statistics</h2><div id="stats-body">Loading...</div></div>
    \\<div class="card"><h2>ARP Table</h2><table><thead><tr><th>Iface</th><th>IP</th><th>MAC</th></tr></thead><tbody id="arp-body"></tbody></table></div>
    \\<div class="card"><h2>NAT Table</h2><table><thead><tr><th>Proto</th><th>LAN</th><th>WAN Port</th><th>Destination</th></tr></thead><tbody id="nat-body"></tbody></table></div>
    \\<div class="card"><h2>DHCP Leases</h2><table><thead><tr><th>IP</th><th>MAC</th></tr></thead><tbody id="lease-body"></tbody></table></div>
    \\<div class="card"><h2>Firewall Rules</h2><table><thead><tr><th>Action</th><th>IP</th></tr></thead><tbody id="fw-body"></tbody></table><h2>Port Forwards</h2><table><thead><tr><th>Proto</th><th>WAN Port</th><th>LAN Target</th></tr></thead><tbody id="fwd-body"></tbody></table></div>
    \\<script>
    \\function f(u,cb){var x=new XMLHttpRequest();x.open('GET',u);x.onload=function(){if(x.status==200)cb(JSON.parse(x.responseText));};x.onerror=function(){document.getElementById('err').textContent='Connection error';};x.send();}
    \\function r(){
    \\f('/api/status',function(d){var h='';if(d.wan)h+='<span class="stat"><span class="label">WAN:</span> <span class="val">'+d.wan.ip+'</span> gw='+d.wan.gateway+' mac='+d.wan.mac+'</span>';if(d.lan)h+='<span class="stat"><span class="label">LAN:</span> <span class="val">'+d.lan.ip+'</span> mac='+d.lan.mac+'</span>';document.getElementById('status-body').innerHTML=h;});
    \\f('/api/ifstat',function(d){var h='';if(d.wan)h+='<span class="stat"><span class="label">WAN</span> rx=<span class="val">'+d.wan.rx+'</span> tx=<span class="val">'+d.wan.tx+'</span> drop='+d.wan.drop+'</span>';if(d.lan)h+=' <span class="stat"><span class="label">LAN</span> rx=<span class="val">'+d.lan.rx+'</span> tx=<span class="val">'+d.lan.tx+'</span> drop='+d.lan.drop+'</span>';document.getElementById('stats-body').innerHTML=h;});
    \\f('/api/arp',function(d){var h='';d.forEach(function(e){h+='<tr><td>'+e.iface+'</td><td>'+e.ip+'</td><td>'+e.mac+'</td></tr>';});document.getElementById('arp-body').innerHTML=h||'<tr><td colspan=3>empty</td></tr>';});
    \\f('/api/nat',function(d){var h='';d.forEach(function(e){h+='<tr><td>'+e.proto+'</td><td>'+e.lan_ip+':'+e.lan_port+'</td><td>:'+e.wan_port+'</td><td>'+e.dst_ip+':'+e.dst_port+'</td></tr>';});document.getElementById('nat-body').innerHTML=h||'<tr><td colspan=4>empty</td></tr>';});
    \\f('/api/leases',function(d){var h='';d.forEach(function(e){h+='<tr><td>'+e.ip+'</td><td>'+e.mac+'</td></tr>';});document.getElementById('lease-body').innerHTML=h||'<tr><td colspan=2>empty</td></tr>';});
    \\f('/api/rules',function(d){var h='';d.firewall.forEach(function(e){h+='<tr><td>'+e.action+'</td><td>'+e.ip+'</td></tr>';});document.getElementById('fw-body').innerHTML=h||'<tr><td colspan=2>none</td></tr>';var g='';d.forwards.forEach(function(e){g+='<tr><td>'+e.proto+'</td><td>:'+e.wan_port+'</td><td>'+e.lan_ip+':'+e.lan_port+'</td></tr>';});document.getElementById('fwd-body').innerHTML=g||'<tr><td colspan=3>none</td></tr>';});
    \\}
    \\r();setInterval(r,5000);
    \\</script></body></html>
;
