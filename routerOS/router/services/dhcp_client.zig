const router = @import("router");

const h = router.net.headers;
const log = router.log;
const main = router.state;
const util = router.util;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

pub const DhcpClientState = enum { idle, discovering, requesting, bound, rebinding };

pub fn sendDiscover() void {
    var pkt: [600]u8 = undefined;
    @memset(&pkt, 0);

    const eth = h.EthernetHeader.parseMut(&pkt) orelse unreachable;
    @memset(&eth.dst_mac, 0xFF);
    @memcpy(&eth.src_mac, &main.wan_iface.mac);
    eth.setEtherType(h.EthernetHeader.IPv4);

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse unreachable;
    ip.ver_ihl = 0x45;
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_UDP;
    @memset(&ip.src_ip, 0);
    @memset(&ip.dst_ip, 0xFF);

    const udp_start: usize = 34;
    const udp = h.UdpHeader.parseMut(pkt[udp_start..]) orelse unreachable;
    udp.setSrcPort(68);
    udp.setDstPort(67);

    const dhcp_start: usize = udp_start + 8;
    pkt[dhcp_start] = 1;
    pkt[dhcp_start + 1] = 1;
    pkt[dhcp_start + 2] = 6;
    pkt[dhcp_start + 3] = 0;

    pkt[dhcp_start + 4] = @truncate(main.dhcp_client_xid >> 24);
    pkt[dhcp_start + 5] = @truncate(main.dhcp_client_xid >> 16);
    pkt[dhcp_start + 6] = @truncate(main.dhcp_client_xid >> 8);
    pkt[dhcp_start + 7] = @truncate(main.dhcp_client_xid);

    @memcpy(pkt[dhcp_start + 28 ..][0..6], &main.wan_iface.mac);

    const magic: usize = dhcp_start + 236;
    pkt[magic] = 0x63;
    pkt[magic + 1] = 0x82;
    pkt[magic + 2] = 0x53;
    pkt[magic + 3] = 0x63;

    var opt: usize = magic + 4;
    pkt[opt] = 53;
    pkt[opt + 1] = 1;
    pkt[opt + 2] = DHCP_DISCOVER;
    opt += 3;
    pkt[opt] = 255;
    opt += 1;

    const total_dhcp = opt - dhcp_start;
    const udp_len: u16 = @truncate(8 + total_dhcp);
    udp.setLength(udp_len);
    const ip_total: u16 = @truncate(20 + udp_len);
    ip.setTotalLen(ip_total);

    ip.computeAndSetChecksum(&pkt);

    const send_len = @max(@as(usize, @intCast(14 + ip_total)), 60);
    _ = main.wan_iface.txSendLocal(pkt[0..send_len]);
    main.dhcp_client_state = .discovering;
    main.dhcp_client_start_ns = util.now();
    log.write(.dhcp_sent_discover);
}

pub fn sendRequest() void {
    var pkt: [600]u8 = undefined;
    @memset(&pkt, 0);

    const eth = h.EthernetHeader.parseMut(&pkt) orelse unreachable;
    @memset(&eth.dst_mac, 0xFF);
    @memcpy(&eth.src_mac, &main.wan_iface.mac);
    eth.setEtherType(h.EthernetHeader.IPv4);

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse unreachable;
    ip.ver_ihl = 0x45;
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_UDP;
    @memset(&ip.src_ip, 0);
    @memset(&ip.dst_ip, 0xFF);

    const udp_start: usize = 34;
    const udp = h.UdpHeader.parseMut(pkt[udp_start..]) orelse unreachable;
    udp.setSrcPort(68);
    udp.setDstPort(67);

    const dhcp_start: usize = udp_start + 8;
    pkt[dhcp_start] = 1;
    pkt[dhcp_start + 1] = 1;
    pkt[dhcp_start + 2] = 6;
    pkt[dhcp_start + 3] = 0;
    pkt[dhcp_start + 4] = @truncate(main.dhcp_client_xid >> 24);
    pkt[dhcp_start + 5] = @truncate(main.dhcp_client_xid >> 16);
    pkt[dhcp_start + 6] = @truncate(main.dhcp_client_xid >> 8);
    pkt[dhcp_start + 7] = @truncate(main.dhcp_client_xid);
    @memcpy(pkt[dhcp_start + 28 ..][0..6], &main.wan_iface.mac);

    const magic: usize = dhcp_start + 236;
    pkt[magic] = 0x63;
    pkt[magic + 1] = 0x82;
    pkt[magic + 2] = 0x53;
    pkt[magic + 3] = 0x63;

    var opt: usize = magic + 4;
    pkt[opt] = 53;
    pkt[opt + 1] = 1;
    pkt[opt + 2] = DHCP_REQUEST;
    opt += 3;

    pkt[opt] = 50;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &main.dhcp_offered_ip);
    opt += 6;

    pkt[opt] = 54;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &main.dhcp_server_ip);
    opt += 6;

    pkt[opt] = 255;
    opt += 1;

    const total_dhcp = opt - dhcp_start;
    const udp_len: u16 = @truncate(8 + total_dhcp);
    udp.setLength(udp_len);
    const ip_total: u16 = @truncate(20 + udp_len);
    ip.setTotalLen(ip_total);

    ip.computeAndSetChecksum(&pkt);

    const send_len = @max(@as(usize, @intCast(14 + ip_total)), 60);
    _ = main.wan_iface.txSendLocal(pkt[0..send_len]);
    main.dhcp_client_state = .requesting;
    main.dhcp_client_start_ns = util.now();
    log.write(.dhcp_sent_request);
}

pub fn sendRebind() void {
    var pkt: [600]u8 = undefined;
    @memset(&pkt, 0);

    const eth = h.EthernetHeader.parseMut(&pkt) orelse unreachable;
    @memset(&eth.dst_mac, 0xFF);
    @memcpy(&eth.src_mac, &main.wan_iface.mac);
    eth.setEtherType(h.EthernetHeader.IPv4);

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse unreachable;
    ip.ver_ihl = 0x45;
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_UDP;
    @memset(&ip.src_ip, 0);
    @memset(&ip.dst_ip, 0xFF);

    const udp_start: usize = 34;
    const udp = h.UdpHeader.parseMut(pkt[udp_start..]) orelse unreachable;
    udp.setSrcPort(68);
    udp.setDstPort(67);

    const dhcp_start: usize = udp_start + 8;
    pkt[dhcp_start] = 1;
    pkt[dhcp_start + 1] = 1;
    pkt[dhcp_start + 2] = 6;
    pkt[dhcp_start + 3] = 0;
    pkt[dhcp_start + 4] = @truncate(main.dhcp_client_xid >> 24);
    pkt[dhcp_start + 5] = @truncate(main.dhcp_client_xid >> 16);
    pkt[dhcp_start + 6] = @truncate(main.dhcp_client_xid >> 8);
    pkt[dhcp_start + 7] = @truncate(main.dhcp_client_xid);
    @memcpy(pkt[dhcp_start + 28 ..][0..6], &main.wan_iface.mac);

    const magic: usize = dhcp_start + 236;
    pkt[magic] = 0x63;
    pkt[magic + 1] = 0x82;
    pkt[magic + 2] = 0x53;
    pkt[magic + 3] = 0x63;

    var opt: usize = magic + 4;
    pkt[opt] = 53;
    pkt[opt + 1] = 1;
    pkt[opt + 2] = DHCP_REQUEST;
    opt += 3;

    pkt[opt] = 50;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &main.dhcp_offered_ip);
    opt += 6;

    // No option 54 (server identifier) — broadcast to any server per RFC 2131

    pkt[opt] = 255;
    opt += 1;

    const total_dhcp = opt - dhcp_start;
    const udp_len: u16 = @truncate(8 + total_dhcp);
    udp.setLength(udp_len);
    const ip_total: u16 = @truncate(20 + udp_len);
    ip.setTotalLen(ip_total);

    ip.computeAndSetChecksum(&pkt);

    const send_len = @max(@as(usize, @intCast(14 + ip_total)), 60);
    _ = main.wan_iface.txSendLocal(pkt[0..send_len]);
    main.dhcp_client_state = .rebinding;
    main.dhcp_client_start_ns = util.now();
    log.write(.dhcp_sent_rebind);
}

pub fn handleResponse(pkt: []const u8, len: u32) void {
    if (main.dhcp_client_state == .idle or main.dhcp_client_state == .bound) return;
    if (len < 282) return;

    const ip = h.Ipv4Header.parse(pkt[14..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;
    if (ip.protocol != h.Ipv4Header.PROTO_UDP) return;

    const udp = h.UdpHeader.parse(pkt[udp_start..]) orelse return;
    if (udp.srcPort() != 67 or udp.dstPort() != 68) return;

    const dhcp_start = udp_start + 8;
    if (dhcp_start + 240 > len) return;
    if (pkt[dhcp_start] != 2) return;

    const xid = @as(u32, pkt[dhcp_start + 4]) << 24 |
        @as(u32, pkt[dhcp_start + 5]) << 16 |
        @as(u32, pkt[dhcp_start + 6]) << 8 |
        pkt[dhcp_start + 7];
    if (xid != main.dhcp_client_xid) return;

    @memcpy(&main.dhcp_offered_ip, pkt[dhcp_start + 16 ..][0..4]);

    const magic_offset = dhcp_start + 236;
    if (pkt[magic_offset] != 0x63 or pkt[magic_offset + 1] != 0x82 or
        pkt[magic_offset + 2] != 0x53 or pkt[magic_offset + 3] != 0x63) return;

    var msg_type: u8 = 0;
    var lease_time_secs: u32 = 0;
    var opt_idx: u32 = magic_offset + 4;
    while (opt_idx + 1 < len) {
        const o = pkt[opt_idx];
        if (o == 255) break;
        if (o == 0) {
            opt_idx += 1;
            continue;
        }
        const olen = pkt[opt_idx + 1];
        if (o == 53 and olen >= 1) msg_type = pkt[opt_idx + 2];
        if (o == 54 and olen >= 4) @memcpy(&main.dhcp_server_ip, pkt[opt_idx + 2 ..][0..4]);
        if (o == 3 and olen >= 4) @memcpy(&main.wan_gateway, pkt[opt_idx + 2 ..][0..4]);
        if (o == 6 and olen >= 4) @memcpy(&main.upstream_dns, pkt[opt_idx + 2 ..][0..4]);
        if (o == 51 and olen >= 4) {
            lease_time_secs = @as(u32, pkt[opt_idx + 2]) << 24 |
                @as(u32, pkt[opt_idx + 3]) << 16 |
                @as(u32, pkt[opt_idx + 4]) << 8 |
                pkt[opt_idx + 5];
        }
        opt_idx += 2 + olen;
    }

    if (msg_type == DHCP_OFFER and main.dhcp_client_state == .discovering) {
        log.writeWithIp(.dhcp_offered, main.dhcp_offered_ip);
        sendRequest();
    } else if (msg_type == DHCP_ACK and (main.dhcp_client_state == .requesting or main.dhcp_client_state == .rebinding)) {
        main.wan_iface.ip = main.dhcp_offered_ip;
        main.dhcp_client_state = .bound;
        main.dhcp_client_bound_ns = util.now();
        if (lease_time_secs > 0) {
            main.dhcp_client_lease_time_ns = @as(u64, lease_time_secs) * 1_000_000_000;
        }
        log.writeWithIp(.dhcp_bound, main.wan_iface.ip);
    }
}

pub fn tick() void {
    const now = util.now();
    if (main.dhcp_client_state == .bound) {
        // T1 renewal at 50% of lease time
        const t1 = main.dhcp_client_lease_time_ns / 2;
        if (now -| main.dhcp_client_bound_ns > t1) {
            log.write(.dhcp_t1_renewal);
            main.dhcp_client_xid +%= 1;
            sendRequest();
            main.dhcp_client_state = .requesting;
            main.dhcp_client_start_ns = now;
        }
        return;
    }
    if (main.dhcp_client_state == .requesting) {
        // T2 rebind at 87.5% of lease time
        const t2 = main.dhcp_client_lease_time_ns / 8 * 7;
        if (now -| main.dhcp_client_bound_ns > t2) {
            log.write(.dhcp_t2_rebind);
            main.dhcp_client_xid +%= 1;
            sendRebind();
            return;
        }
        // Retry unicast request every 10s
        if (now -| main.dhcp_client_start_ns > 10_000_000_000) {
            log.write(.dhcp_timeout_request);
            main.dhcp_client_xid +%= 1;
            sendRequest();
            main.dhcp_client_start_ns = now;
        }
        return;
    }
    if (main.dhcp_client_state == .rebinding) {
        // Lease expired — restart from scratch
        if (now -| main.dhcp_client_bound_ns > main.dhcp_client_lease_time_ns) {
            log.write(.dhcp_lease_expired);
            main.dhcp_client_xid +%= 1;
            sendDiscover();
            return;
        }
        // Retry rebind every 10s
        if (now -| main.dhcp_client_start_ns > 10_000_000_000) {
            log.write(.dhcp_timeout_rebind);
            main.dhcp_client_xid +%= 1;
            sendRebind();
        }
        return;
    }
    if (main.dhcp_client_state == .idle) return;
    // Timeout for discover — retry after 10s
    if (now -| main.dhcp_client_start_ns > 10_000_000_000) {
        log.write(.dhcp_timeout_retry);
        main.dhcp_client_xid +%= 1;
        sendDiscover();
    }
}
