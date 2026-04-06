const lib = @import("lib");
const router = @import("router");

const arp = router.protocols.arp;
const dhcp_client = router.protocols.dhcp_client;
const dhcp_server = router.protocols.dhcp_server;
const dhcpv6_client = router.protocols.ipv6.dhcp_client;
const dns = router.protocols.dns;
const firewall = router.protocols.ipv4.firewall;
const firewall6 = router.protocols.ipv6.firewall;
const h = router.hal.headers;
const icmpv6 = router.protocols.ipv6.icmp;
const main = router.state;
const nat = router.protocols.ipv4.nat;
const ndp = router.protocols.ipv6.ndp;
const pcp = router.protocols.pcp;
const ping_mod = router.protocols.ipv4.icmp;
const slaac = router.protocols.ipv6.slaac;
const tcp_stack = router.protocols.tcp_stack;
const udp_fwd = router.protocols.udp_fwd;
const upnp = router.protocols.upnp;
const util = router.util;

const iface_mod = router.hal.iface;

const Iface = iface_mod.Iface;
const Interface = main.Interface;

pub const PacketAction = enum {
    consumed, // Packet fully handled, return RX buffer to hardware
    forward_wan, // Forward to WAN (zero-copy: headers modified in-place)
    forward_lan, // Forward to LAN (zero-copy: headers modified in-place)
};

pub fn handleIcmp(role: Interface, pkt: []u8, len: u32) ?[]u8 {
    const ip = h.Ipv4Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return null;
    if (len < h.EthernetHeader.LEN + h.Ipv4Header.MIN_LEN or ip.protocol != h.Ipv4Header.PROTO_ICMP) return null;
    const ip_hdr_len = ip.headerLen();
    const icmp_start = h.EthernetHeader.LEN + ip_hdr_len;
    if (icmp_start + h.IcmpHeader.LEN > len) return null;
    const icmp = h.IcmpHeader.parseMut(pkt[icmp_start..]) orelse return null;
    if (icmp.icmp_type != h.IcmpHeader.TYPE_ECHO_REQUEST) return null;
    const ifc = main.getIface(role);
    @memcpy(pkt[0..6], pkt[6..12]);
    @memcpy(pkt[6..12], &ifc.mac);
    var tmp: [4]u8 = undefined;
    @memcpy(&tmp, &ip.src_ip);
    ip.src_ip = ip.dst_ip;
    ip.dst_ip = tmp;
    icmp.icmp_type = h.IcmpHeader.TYPE_ECHO_REPLY;
    icmp.computeAndSetChecksum(pkt[icmp_start..len]);
    ip.computeAndSetChecksum(pkt);
    return pkt[0..len];
}

/// Clamp TCP MSS option on SYN/SYN-ACK packets to 1460 (1500 MTU - 40).
/// Only modifies packets with SYN flag set and MSS option present.
fn clampMss(pkt: []u8, len: u32) void {
    const ip = h.Ipv4Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const tcp_start = h.EthernetHeader.LEN + ip_hdr_len;
    if (tcp_start + h.TcpHeader.MIN_LEN > len) return;

    const tcp = h.TcpHeader.parseMut(pkt[tcp_start..]) orelse return;
    if (tcp.flags & h.TcpHeader.SYN == 0) return; // Not SYN

    const tcp_data_offset = tcp.dataOffset();
    if (tcp_data_offset <= h.TcpHeader.MIN_LEN) return; // No options

    // Walk TCP options looking for MSS (kind=2, len=4)
    var i: usize = tcp_start + 20;
    const opts_end = tcp_start + tcp_data_offset;
    while (i + 1 < opts_end and i + 1 < len) {
        const kind = pkt[i];
        if (kind == 0) break; // End of options
        if (kind == 1) { // NOP
            i += 1;
            continue;
        }
        const opt_len = pkt[i + 1];
        if (opt_len < 2) break;
        if (kind == 2 and opt_len == 4 and i + 3 < len) {
            const mss = util.readU16Be(pkt[i + 2 ..][0..2]);
            if (mss > 1460) {
                util.writeU16Be(pkt[i + 2 ..][0..2], 1460);
                // Recompute TCP checksum
                util.recomputeTransportChecksum(pkt, tcp_start, len, 6);
            }
            return;
        }
        i += opt_len;
    }
}

/// Send an ICMP error message (TTL exceeded, dest unreachable, etc.)
/// back to the source of the original packet.
pub fn sendIcmpError(role: Interface, orig_pkt: []const u8, orig_len: u32, icmp_type: u8, icmp_code: u8) void {
    if (orig_len < h.EthernetHeader.LEN + h.Ipv4Header.MIN_LEN) return;
    const ifc = main.getIface(role);

    // ICMP error payload: original IP header + first 8 bytes of original payload
    const orig_ip = h.Ipv4Header.parse(orig_pkt[h.EthernetHeader.LEN..]) orelse return;
    const orig_ihl = orig_ip.headerLen();
    const payload_start: usize = h.EthernetHeader.LEN; // start of original IP header
    const payload_end = @min(payload_start + orig_ihl + 8, orig_len);
    const payload_len: u16 = @intCast(payload_end - payload_start);

    // Build response: 14 eth + 20 IP + 8 ICMP header + payload
    const icmp_total: u16 = @as(u16, h.IcmpHeader.LEN) + payload_len;
    const ip_total: u16 = @as(u16, h.Ipv4Header.MIN_LEN) + icmp_total;
    const frame_len: usize = @max(@as(usize, @as(u16, h.EthernetHeader.LEN) + ip_total), 60);

    var pkt: [600]u8 = undefined;
    @memset(pkt[0..frame_len], 0);

    // Ethernet: reply to source
    @memcpy(pkt[0..6], orig_pkt[6..12]); // dst = original src MAC
    @memcpy(pkt[6..12], &ifc.mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IP header
    pkt[14] = 0x45; // version 4, IHL 5
    util.writeU16Be(pkt[16..18], ip_total);
    const ip = h.Ipv4Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return;
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_ICMP;
    ip.src_ip = ifc.ip;
    ip.dst_ip = orig_ip.src_ip;

    // IP checksum
    ip.computeAndSetChecksum(&pkt);

    // ICMP header
    const icmp_start: usize = h.EthernetHeader.LEN + h.Ipv4Header.MIN_LEN;
    const icmp_hdr = h.IcmpHeader.parseMut(pkt[icmp_start..]) orelse return;
    icmp_hdr.icmp_type = icmp_type;
    icmp_hdr.code = icmp_code;
    // bytes 4-7 are unused (zero) for TTL exceeded and most unreachable codes

    // ICMP payload: original IP header + 8 bytes
    @memcpy(pkt[icmp_start + h.IcmpHeader.LEN ..][0..payload_len], orig_pkt[payload_start..payload_end]);

    // ICMP checksum
    icmp_hdr.computeAndSetChecksum(pkt[icmp_start..][0..icmp_total]);

    _ = ifc.txSendLocal(pkt[0..frame_len], .dataplane);
}

fn isIpv6ForUs(ifc: *const Iface, dst_ip6: [16]u8) bool {
    if (util.eql(&dst_ip6, &ifc.ip6_link_local)) return true;
    if (ifc.ip6_global_valid and util.eql(&dst_ip6, &ifc.ip6_global)) return true;
    // Solicited-node multicast for our link-local
    const snm_ll = util.solicitedNodeMulticast(ifc.ip6_link_local);
    if (util.eql(&dst_ip6, &snm_ll)) return true;
    if (ifc.ip6_global_valid) {
        const snm_gl = util.solicitedNodeMulticast(ifc.ip6_global);
        if (util.eql(&dst_ip6, &snm_gl)) return true;
    }
    // All-nodes multicast (ff02::1)
    if (dst_ip6[0] == 0xff and dst_ip6[1] == 0x02 and dst_ip6[15] == 0x01 and
        util.isAllZeros(dst_ip6[2..15])) return true;
    // All-routers multicast (ff02::2)
    if (dst_ip6[0] == 0xff and dst_ip6[1] == 0x02 and dst_ip6[15] == 0x02 and
        util.isAllZeros(dst_ip6[2..15])) return true;
    return false;
}

fn processIpv6(role: Interface, pkt: []u8, len: u32) PacketAction {
    if (len < h.EthernetHeader.LEN + h.Ipv6Header.LEN) return .consumed;

    const ip6 = h.Ipv6Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return .consumed;
    const ifc = main.getIface(role);
    const is_for_me = isIpv6ForUs(ifc, ip6.dst_ip);

    // Learn source neighbor
    var src_mac: [6]u8 = undefined;
    @memcpy(&src_mac, pkt[6..12]);
    const ndp_tbl = if (role == .wan) &main.wan_ndp_table else &main.lan_ndp_table;
    if (!util.isAllZeros(&ip6.src_ip)) ndp.learn(ndp_tbl, ip6.src_ip, src_mac, false);

    if (ip6.next_header == 58 and len >= h.EthernetHeader.LEN + h.Ipv6Header.LEN + 1) {
        const icmpv6_type = pkt[h.EthernetHeader.LEN + h.Ipv6Header.LEN];

        // NDP: NS/NA
        if (icmpv6_type == 135 or icmpv6_type == 136) {
            if (ndp.handle(role, pkt, len)) |reply| {
                _ = ifc.txSendLocal(reply, .dataplane);
            }
            return .consumed;
        }
        // Router Solicitation on LAN
        if (icmpv6_type == 133 and role == .lan) {
            slaac.handleRouterSolicitation(pkt, len);
            return .consumed;
        }
        // Router Advertisement on WAN (learn gateway)
        if (icmpv6_type == 134 and role == .wan) {
            return .consumed;
        }
        // Echo Request
        if (icmpv6_type == 128 and is_for_me) {
            if (icmpv6.handleEchoRequest(role, pkt, len)) |reply| {
                _ = ifc.txSendLocal(reply, .dataplane);
            }
            return .consumed;
        }
        // Echo Reply
        if (icmpv6_type == 129) {
            icmpv6.handleEchoReply(pkt, len);
            return .consumed;
        }
    }

    // UDP — check for DHCPv6
    if (ip6.next_header == 17 and is_for_me and len >= h.EthernetHeader.LEN + h.Ipv6Header.LEN + 4) {
        const udp_dst = util.readU16Be(pkt[h.EthernetHeader.LEN + h.Ipv6Header.LEN + 2 ..][0..2]);
        if (udp_dst == 546 and role == .wan) {
            dhcpv6_client.handleResponse(pkt, len);
            return .consumed;
        }
    }

    if (is_for_me) return .consumed;

    // Not for us — forward (no NAT for IPv6)
    if (ip6.hop_limit <= 1) {
        icmpv6.sendError(role, pkt, len, 3, 0); // Time Exceeded
        return .consumed;
    }
    ip6.hop_limit -= 1; // Decrement hop limit (no IP checksum to update!)

    if (role == .lan and main.has_lan) {
        // LAN → WAN
        firewall6.allowOutbound(pkt, len);
        const gw_mac = ndp.lookup(&main.wan_ndp_table, main.wan_gateway_ip6) orelse {
            ndp.sendNeighborSolicitation(.wan, main.wan_gateway_ip6);
            return .consumed;
        };
        @memcpy(pkt[0..6], &gw_mac);
        @memcpy(pkt[6..12], &main.wan_iface.mac);
        return .forward_wan;
    }
    if (role == .wan and main.has_lan) {
        // WAN → LAN
        if (!firewall6.allowInbound(pkt, len)) return .consumed;
        const inner_dst = ip6.dst_ip;
        const dst_mac = ndp.lookup(&main.lan_ndp_table, inner_dst) orelse {
            ndp.sendNeighborSolicitation(.lan, inner_dst);
            return .consumed;
        };
        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &main.lan_iface.mac);
        return .forward_lan;
    }

    return .consumed;
}

/// Process a received packet. Returns whether it should be forwarded zero-copy.
/// For forwarded packets, headers are modified IN-PLACE in the DMA buffer.
pub fn process(role: Interface, pkt: []u8, len: u32) PacketAction {
    if (len < h.EthernetHeader.LEN) return .consumed;
    const ifc = main.getIface(role);
    const eth = h.EthernetHeader.parse(pkt) orelse return .consumed;
    const ethertype = eth.etherType();

    if (ethertype == h.EthernetHeader.ARP) {
        // ARP: learn, reply, never forwarded
        if (len >= h.EthernetHeader.LEN + h.ArpHeader.LEN) {
            const arp_hdr = h.ArpHeader.parse(pkt[h.EthernetHeader.LEN..]) orelse return .consumed;
            arp.learn(&ifc.arp_table, arp_hdr.sender_ip, arp_hdr.sender_mac);
            udp_fwd.drainPending();
            if (main.ping_state == .arp_pending and main.ping_iface == role) {
                if (arp.lookup(&ifc.arp_table, main.ping_target_ip)) |mac| {
                    @memcpy(&main.ping_target_mac, &mac);
                    ping_mod.sendEchoRequest();
                }
            }
            if (main.traceroute_state == .arp_pending and main.traceroute_iface == role) {
                // For non-local traceroute, resolve gateway MAC
                const resolve_ip = if (main.traceroute_iface == .wan) main.wan_gateway else main.traceroute_target_ip;
                if (arp.lookup(&ifc.arp_table, resolve_ip)) |mac| {
                    @memcpy(&main.traceroute_target_mac, &mac);
                    ping_mod.sendTracerouteProbe();
                }
            }
        }
        if (arp.handle(role, pkt, len)) |reply| {
            _ = ifc.txSendLocal(reply, .dataplane);
        }
        return .consumed;
    }

    if (ethertype == h.EthernetHeader.IPv6) return processIpv6(role, pkt, len);

    if (ethertype != h.EthernetHeader.IPv4 or len < h.EthernetHeader.LEN + h.Ipv4Header.MIN_LEN) return .consumed;

    // IPv4 packet
    const ip = h.Ipv4Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return .consumed;
    const dst_ip = ip.dst_ip;
    const my_ip = &ifc.ip;
    const is_for_me = util.eql(&dst_ip, my_ip) or util.eql(&dst_ip, &main.lan_broadcast) or
        (dst_ip[0] == 255 and dst_ip[1] == 255 and dst_ip[2] == 255 and dst_ip[3] == 255) or
        (role == .lan and (dst_ip[0] & 0xF0) == 0xE0); // LAN multicast (224.0.0.0/4)

    if (is_for_me) {
        // Packet addressed to us — handle locally, never zero-copy forward

        // TCP — HTTP server on LAN port 80
        if (ip.protocol == h.Ipv4Header.PROTO_TCP and role == .lan) {
            if (tcp_stack.handleTcp(pkt, len)) return .consumed;
        }

        if (ip.protocol == h.Ipv4Header.PROTO_UDP) {
            const ip_hdr_len = ip.headerLen();
            const udp_start = h.EthernetHeader.LEN + ip_hdr_len;
            if (udp_start + 4 <= len) {
                const udp_dst = util.readU16Be(pkt[udp_start + 2 ..][0..2]);
                if (udp_dst == 68 and role == .wan) {
                    dhcp_client.handleResponse(pkt, len);
                    return .consumed;
                }
                if (udp_dst == 67 and role == .lan) {
                    dhcp_server.handle(pkt, len);
                    return .consumed;
                }
                if (udp_dst == dns.DNS_PORT and role == .lan) {
                    dns.handleFromLan(pkt, len);
                    return .consumed;
                }
                if (udp_dst == upnp.SSDP_PORT and role == .lan) {
                    upnp.handleSsdp(pkt, len);
                    return .consumed;
                }
                if (udp_dst == pcp.PCP_PORT and role == .lan) {
                    pcp.handleRequest(pkt, len);
                    return .consumed;
                }
                if (role == .wan) {
                    const udp_src_port = util.readU16Be(pkt[udp_start..][0..2]);
                    if (udp_src_port == dns.DNS_PORT) {
                        dns.handleFromWan(pkt, len);
                        return .consumed;
                    }
                }
                if (udp_start + 8 <= len) {
                    const src_ip_udp = ip.src_ip;
                    const udp_src = util.readU16Be(pkt[udp_start..][0..2]);
                    if (udp_fwd.forwardToApp(src_ip_udp, udp_src, udp_dst, pkt[udp_start + 8 .. len])) return .consumed;
                }
                // Check port forwarding before declaring unreachable
                if (role == .wan and main.has_lan) {
                    if (firewall.handlePortForward(pkt, len)) return .consumed;
                    if (nat.forwardWanToLan(pkt, len)) return .forward_lan;
                }
                // No handler matched — send ICMP Port Unreachable (Type 3, Code 3)
                // Don't send for broadcasts
                if (!util.eql(&dst_ip, &main.lan_broadcast) and
                    dst_ip[0] != 255)
                {
                    sendIcmpError(role, pkt, len, 3, 3);
                }
                return .consumed;
            }
        }
        ping_mod.handleEchoReply(pkt, len);
        ping_mod.handleTimeExceeded(pkt, len);
        ping_mod.handleTracerouteEchoReply(pkt, len);
        if (handleIcmp(role, pkt, len)) |reply| {
            _ = ifc.txSendLocal(reply, .dataplane);
        } else if (role == .wan and main.has_lan) {
            if (firewall.handlePortForward(pkt, len)) return .consumed;
            if (nat.forwardWanToLan(pkt, len)) return .forward_lan;
        }
        return .consumed;
    }

    // Packet not for us — forward to the other interface
    // Check TTL before forwarding
    if (ip.ttl <= 1) {
        // TTL expired — send ICMP Time Exceeded (Type 11, Code 0)
        sendIcmpError(role, pkt, len, 11, 0);
        return .consumed;
    }
    // Decrement TTL and recompute IP checksum
    ip.ttl -= 1;
    ip.computeAndSetChecksum(pkt);

    // TCP MSS clamping on SYN/SYN-ACK traversing the router
    if (ip.protocol == h.Ipv4Header.PROTO_TCP) clampMss(pkt, len);

    if (role == .lan and main.has_lan) {
        if (firewall.reversePortForward(pkt, len)) return .forward_wan;
        if (nat.forwardLanToWan(pkt, len)) return .forward_wan;
    }

    return .consumed;
}
