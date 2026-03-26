const router = @import("router");

const arp = router.net.arp;
const h = router.net.headers;
const main = router.state;
const util = router.util;
const assert = util.assert;

pub const RULES_SIZE = 64;
pub const PORT_FWD_SIZE = 32;

pub const FirewallAction = enum { allow, block };

pub const FirewallRule = struct {
    valid: bool,
    action: FirewallAction,
    src_ip: [4]u8,
    src_mask: [4]u8,
    protocol: u8,
    dst_port: u16,
};

pub const empty_rule = FirewallRule{
    .valid = false,
    .action = .block,
    .src_ip = .{ 0, 0, 0, 0 },
    .src_mask = .{ 0, 0, 0, 0 },
    .protocol = 0,
    .dst_port = 0,
};

pub const PortForward = struct {
    valid: bool,
    protocol: util.Protocol,
    wan_port: u16,
    lan_ip: [4]u8,
    lan_port: u16,
};

pub const empty_fwd = PortForward{
    .valid = false,
    .protocol = .tcp,
    .wan_port = 0,
    .lan_ip = .{ 0, 0, 0, 0 },
    .lan_port = 0,
};

pub fn check(rules: *const [RULES_SIZE]FirewallRule, src_ip: [4]u8, protocol: u8, dst_port: u16) FirewallAction {
    for (rules) |*r| {
        if (!r.valid) continue;
        const ip_match = (src_ip[0] & r.src_mask[0]) == (r.src_ip[0] & r.src_mask[0]) and
            (src_ip[1] & r.src_mask[1]) == (r.src_ip[1] & r.src_mask[1]) and
            (src_ip[2] & r.src_mask[2]) == (r.src_ip[2] & r.src_mask[2]) and
            (src_ip[3] & r.src_mask[3]) == (r.src_ip[3] & r.src_mask[3]);
        if (!ip_match) continue;
        if (r.protocol != 0 and r.protocol != protocol) continue;
        if (r.dst_port != 0 and r.dst_port != dst_port) continue;
        return r.action;
    }
    return .allow;
}

pub fn portFwdLookup(forwards: *const [PORT_FWD_SIZE]PortForward, proto: util.Protocol, wan_port: u16) ?*const PortForward {
    for (forwards) |*f| {
        if (f.valid and f.protocol == proto and f.wan_port == wan_port) return f;
    }
    return null;
}

pub fn portFwdAdd(forwards: *[PORT_FWD_SIZE]PortForward, proto: util.Protocol, wan_port: u16, lip: [4]u8, lport: u16) bool {
    for (forwards) |*f| {
        if (!f.valid) {
            f.* = .{ .valid = true, .protocol = proto, .wan_port = wan_port, .lan_ip = lip, .lan_port = lport };
            return true;
        }
    }
    return false;
}

pub fn handlePortForward(pkt: []u8, len: u32) bool {
    if (!main.has_lan) return false;
    if (len < 34) return false;

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return false;
    if (ip.protocol != h.Ipv4Header.PROTO_TCP and ip.protocol != h.Ipv4Header.PROTO_UDP) return false;

    const transport_start = 14 + ip.headerLen();
    if (transport_start + 4 > len) return false;

    const udp = h.UdpHeader.parseMut(pkt[transport_start..]) orelse return false;
    const proto: util.Protocol = if (ip.protocol == h.Ipv4Header.PROTO_TCP) .tcp else .udp;

    const fwd = portFwdLookup(&main.port_forwards, proto, udp.dstPort()) orelse return false;

    const dst_mac = arp.lookup(&main.lan_iface.arp_table, fwd.lan_ip) orelse {
        arp.sendRequest(.lan, fwd.lan_ip);
        return true;
    };

    @memcpy(pkt[0..6], &dst_mac);
    @memcpy(pkt[6..12], &main.lan_iface.mac);
    @memcpy(&ip.dst_ip, &fwd.lan_ip);
    udp.setDstPort(fwd.lan_port);

    util.recomputeTransportChecksum(pkt, transport_start, len, ip.protocol);

    ip.computeAndSetChecksum(pkt);

    main.lan_iface.stats.tx_packets += 1;
    main.lan_iface.stats.tx_bytes += len;
    _ = main.lan_iface.txSendLocal(pkt[0..len]);
    return true;
}

/// Reverse DNAT for port-forwarded return traffic (LAN server → WAN client).
/// Rewrites src IP/port from LAN server back to router WAN IP:wan_port.
/// Returns true if headers were rewritten (caller should forward to WAN).
pub fn reversePortForward(pkt: []u8, len: u32) bool {
    if (len < 34) return false;

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return false;
    if (ip.protocol != h.Ipv4Header.PROTO_TCP and ip.protocol != h.Ipv4Header.PROTO_UDP) return false;

    const transport_start = 14 + ip.headerLen();
    if (transport_start + 4 > len) return false;

    const udp = h.UdpHeader.parseMut(pkt[transport_start..]) orelse return false;
    const proto: util.Protocol = if (ip.protocol == h.Ipv4Header.PROTO_TCP) .tcp else .udp;

    for (&main.port_forwards) |*f| {
        if (!f.valid) continue;
        if (f.protocol != proto) continue;
        if (!util.eql(&f.lan_ip, &ip.src_ip)) continue;
        if (f.lan_port != udp.srcPort()) continue;

        // Match — rewrite src to router WAN IP:wan_port
        const gateway_mac = arp.lookup(&main.wan_iface.arp_table, main.wan_gateway) orelse {
            arp.sendRequest(.wan, main.wan_gateway);
            return false;
        };

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &main.wan_iface.mac);
        @memcpy(&ip.src_ip, &main.wan_iface.ip);
        udp.setSrcPort(f.wan_port);

        ip.computeAndSetChecksum(pkt);

        util.recomputeTransportChecksum(pkt, transport_start, len, ip.protocol);
        return true;
    }
    return false;
}
