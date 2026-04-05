const router = @import("router");

const h = router.hal.headers;
const main = router.state;
const util = router.util;

pub const SSDP_PORT: u16 = 1900;

// UPnP device/service type URNs
const WANIP_SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:1";
const ROOT_DEVICE = "upnp:rootdevice";
const IGD_DEVICE = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const UUID = "uuid:zag-router-1";

pub fn handleSsdp(pkt: []u8, len: u32) void {
    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;

    const payload_start = udp_start + 8;
    if (payload_start >= len) return;
    const payload = pkt[payload_start..len];

    // Only handle M-SEARCH requests
    if (!startsWith(payload, "M-SEARCH")) return;

    // Check for relevant search targets
    const is_all = contains(payload, "ssdp:all");
    const is_rootdev = contains(payload, "upnp:rootdevice");
    const is_igd = contains(payload, "InternetGatewayDevice");
    const is_wanip = contains(payload, "WANIPConnection");
    if (!is_all and !is_rootdev and !is_igd and !is_wanip) return;

    const src_ip = ip.src_ip;
    const src_mac = pkt[6..12].*;
    const src_port = util.readU16Be(pkt[udp_start..][0..2]);

    // Build SSDP response with LOCATION pointing to our HTTP server
    var resp_buf: [768]u8 = undefined;
    var p: usize = 0;

    p = appendStr(&resp_buf, p, "HTTP/1.1 200 OK\r\n");
    p = appendStr(&resp_buf, p, "CACHE-CONTROL: max-age=1800\r\n");
    p = appendStr(&resp_buf, p, "LOCATION: http://");
    p = appendIp(&resp_buf, p, main.lan_iface.ip);
    p = appendStr(&resp_buf, p, "/upnp/rootDesc.xml\r\n");
    p = appendStr(&resp_buf, p, "SERVER: Zag/1.0 UPnP/1.0 ZagRouter/1.0\r\n");

    if (is_wanip) {
        p = appendStr(&resp_buf, p, "ST: " ++ WANIP_SERVICE ++ "\r\n");
        p = appendStr(&resp_buf, p, "USN: " ++ UUID ++ "::" ++ WANIP_SERVICE ++ "\r\n");
    } else if (is_igd) {
        p = appendStr(&resp_buf, p, "ST: " ++ IGD_DEVICE ++ "\r\n");
        p = appendStr(&resp_buf, p, "USN: " ++ UUID ++ "::" ++ IGD_DEVICE ++ "\r\n");
    } else {
        p = appendStr(&resp_buf, p, "ST: " ++ ROOT_DEVICE ++ "\r\n");
        p = appendStr(&resp_buf, p, "USN: " ++ UUID ++ "::" ++ ROOT_DEVICE ++ "\r\n");
    }

    p = appendStr(&resp_buf, p, "\r\n");

    sendUdpResponse(src_ip, src_mac, src_port, resp_buf[0..p]);
}

fn sendUdpResponse(dst_ip: [4]u8, dst_mac: [6]u8, dst_port: u16, payload: []const u8) void {
    const udp_len: u16 = @intCast(8 + payload.len);
    const ip_total: u16 = 20 + udp_len;
    const frame_len: usize = 14 + @as(usize, ip_total);

    var frame: [1024]u8 = undefined;
    if (frame_len > frame.len) return;

    // Ethernet header
    @memcpy(frame[0..6], &dst_mac);
    @memcpy(frame[6..12], &main.lan_iface.mac);
    frame[12] = 0x08;
    frame[13] = 0x00;

    // IP header
    const ip = h.Ipv4Header.parseMut(frame[14..]) orelse return;
    ip.ver_ihl = 0x45;
    ip.setTotalLen(ip_total);
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_UDP;
    @memcpy(&ip.src_ip, &main.lan_iface.ip);
    @memcpy(&ip.dst_ip, &dst_ip);
    ip.computeAndSetChecksum(&frame);

    // UDP header
    const udp = h.UdpHeader.parseMut(frame[34..]) orelse return;
    udp.setSrcPort(SSDP_PORT);
    udp.setDstPort(dst_port);
    udp.setLength(udp_len);
    udp.zeroChecksum();

    // Payload
    @memcpy(frame[42..][0..payload.len], payload);

    _ = main.lan_iface.txSendLocal(frame[0..frame_len], .dataplane);
}

fn startsWith(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return util.eql(haystack[0..prefix.len], @as([]const u8, prefix));
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (util.eql(haystack[i..][0..needle.len], @as([]const u8, needle))) return true;
    }
    return false;
}

fn appendStr(buf: []u8, pos: usize, s: []const u8) usize {
    const n = @min(s.len, buf.len -| pos);
    if (n == 0) return pos;
    @memcpy(buf[pos..][0..n], s[0..n]);
    return pos + n;
}

fn appendIp(buf: []u8, pos: usize, ip: [4]u8) usize {
    var p = pos;
    for (ip, 0..) |octet, i| {
        if (i > 0) {
            if (p < buf.len) {
                buf[p] = '.';
                p += 1;
            }
        }
        p = appendDecimal(buf, p, octet);
    }
    return p;
}

fn appendDecimal(buf: []u8, pos: usize, val: u8) usize {
    var p = pos;
    if (val >= 100) {
        if (p < buf.len) {
            buf[p] = '0' + val / 100;
            p += 1;
        }
    }
    if (val >= 10) {
        if (p < buf.len) {
            buf[p] = '0' + (val / 10) % 10;
            p += 1;
        }
    }
    if (p < buf.len) {
        buf[p] = '0' + val % 10;
        p += 1;
    }
    return p;
}
