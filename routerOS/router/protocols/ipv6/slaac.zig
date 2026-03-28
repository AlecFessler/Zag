const router = @import("router");

const h = router.hal.headers;
const main = router.state;
const util = router.util;

const RA_INTERVAL_NS: u64 = 60_000_000_000; // 60 seconds
const ALL_NODES: [16]u8 = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

/// Handle Router Solicitation (type 133) from a LAN device.
pub fn handleRouterSolicitation(pkt: []const u8, len: u32) void {
    if (len < 54) return;
    const eth = h.EthernetHeader.parse(pkt) orelse return;
    const ip6 = h.Ipv6Header.parse(pkt[14..]) orelse return;
    var src_mac: [6]u8 = undefined;
    var src_ip6: [16]u8 = undefined;
    @memcpy(&src_mac, &eth.src_mac);
    @memcpy(&src_ip6, &ip6.src_ip);

    // Send solicited RA to the requester
    if (util.isAllZeros(&src_ip6)) {
        sendRA(null, null); // Unspecified source → multicast
    } else {
        sendRA(src_mac, src_ip6);
    }
}

/// Send a Router Advertisement on the LAN interface.
/// If dst is null, sends to all-nodes multicast (ff02::1).
pub fn sendRA(dst_mac: ?[6]u8, dst_ip6: ?[16]u8) void {
    if (!main.has_lan) return;
    const ifc = &main.lan_iface;

    var pkt: [150]u8 = undefined;
    @memset(&pkt, 0);

    // Ethernet
    const eth = h.EthernetHeader.parseMut(&pkt) orelse return;
    if (dst_mac) |dm| {
        @memcpy(&eth.dst_mac, &dm);
    } else {
        const mcast_mac = util.multicastMac6(ALL_NODES);
        @memcpy(&eth.dst_mac, &mcast_mac);
    }
    @memcpy(&eth.src_mac, &ifc.mac);
    eth.setEtherType(h.EthernetHeader.IPv6);

    // IPv6
    const ip6 = h.Ipv6Header.parseMut(pkt[14..]) orelse return;
    ip6.ver_tc_fl[0] = 0x60;
    ip6.next_header = 58; // ICMPv6
    ip6.hop_limit = 255;
    @memcpy(&ip6.src_ip, &ifc.ip6_link_local); // source = link-local
    if (dst_ip6) |di| {
        @memcpy(&ip6.dst_ip, &di);
    } else {
        @memcpy(&ip6.dst_ip, &ALL_NODES);
    }

    // ICMPv6 Router Advertisement (type 134)
    var pos: usize = 54;
    pkt[pos] = 134; // type
    pkt[pos + 1] = 0; // code
    // checksum at pos+2..pos+4
    pkt[pos + 4] = 64; // current hop limit
    pkt[pos + 5] = 0; // flags: M=0, O=0
    // router lifetime = 1800s (big-endian)
    util.writeU16Be(pkt[pos + 6 ..][0..2], 1800);
    // reachable time = 0 (unspecified)
    // retrans timer = 0 (unspecified)
    pos += 16; // RA header is 16 bytes

    // Source Link-Layer Address option (type 1)
    pkt[pos] = 1;
    pkt[pos + 1] = 1; // length = 1 (8 bytes)
    @memcpy(pkt[pos + 2 ..][0..6], &ifc.mac);
    pos += 8;

    // Prefix Information option (type 3) — only if we have a delegated prefix
    if (main.delegated_prefix.valid) {
        pkt[pos] = 3; // type
        pkt[pos + 1] = 4; // length = 4 (32 bytes)
        pkt[pos + 2] = main.delegated_prefix.prefix_len; // prefix length
        pkt[pos + 3] = 0xC0; // L + A flags (on-link + autonomous)
        // Valid lifetime = 7200s
        pkt[pos + 4] = 0;
        pkt[pos + 5] = 0;
        pkt[pos + 6] = 0x1C;
        pkt[pos + 7] = 0x20;
        // Preferred lifetime = 3600s
        pkt[pos + 8] = 0;
        pkt[pos + 9] = 0;
        pkt[pos + 10] = 0x0E;
        pkt[pos + 11] = 0x10;
        // Reserved (4 bytes, zero)
        @memcpy(pkt[pos + 16 ..][0..16], &main.delegated_prefix.prefix);
        pos += 32;
    }

    // Fill IPv6 payload length
    const payload_len: u16 = @truncate(pos - 54);
    ip6.setPayloadLen(payload_len);

    // ICMPv6 checksum
    var src_ip6_cs: [16]u8 = undefined;
    var dst_ip6_cs: [16]u8 = undefined;
    @memcpy(&src_ip6_cs, &ip6.src_ip);
    @memcpy(&dst_ip6_cs, &ip6.dst_ip);
    const cs = util.computeIcmpv6Checksum(src_ip6_cs, dst_ip6_cs, pkt[54..pos]);
    pkt[56] = @truncate(cs >> 8);
    pkt[57] = @truncate(cs);

    _ = ifc.txSendLocal(pkt[0..pos], .dataplane);
}

/// Periodic tick — send unsolicited RAs on LAN.
pub fn tick() void {
    if (!main.has_lan) return;
    const now = util.now();
    if (now -% main.last_ra_ns > RA_INTERVAL_NS) {
        main.last_ra_ns = now;
        sendRA(null, null);
    }
}
