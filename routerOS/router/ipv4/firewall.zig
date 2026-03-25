const router = @import("router");

const arp = router.net.arp;
const main = router.state;
const util = router.util;

pub const RULES_SIZE = 32;
pub const PORT_FWD_SIZE = 16;

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
    .valid = false, .action = .block,
    .src_ip = .{ 0, 0, 0, 0 }, .src_mask = .{ 0, 0, 0, 0 },
    .protocol = 0, .dst_port = 0,
};

pub const PortForward = struct {
    valid: bool,
    protocol: util.Protocol,
    wan_port: u16,
    lan_ip: [4]u8,
    lan_port: u16,
};

pub const empty_fwd = PortForward{
    .valid = false, .protocol = .tcp, .wan_port = 0,
    .lan_ip = .{ 0, 0, 0, 0 }, .lan_port = 0,
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

    const protocol = pkt[23];
    if (protocol != 6 and protocol != 17) return false;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const transport_start = 14 + ip_hdr_len;
    if (transport_start + 4 > len) return false;

    const dst_port = util.readU16Be(pkt[transport_start + 2 ..][0..2]);
    const proto: util.Protocol = if (protocol == 6) .tcp else .udp;

    const fwd = portFwdLookup(&main.port_forwards, proto, dst_port) orelse return false;

    const dst_mac = arp.lookup(&main.lan_iface.arp_table, fwd.lan_ip) orelse {
        arp.sendRequest(.lan, fwd.lan_ip);
        return true;
    };

    var old_dst_ip: [4]u8 = undefined;
    @memcpy(&old_dst_ip, pkt[30..34]);

    @memcpy(pkt[0..6], &dst_mac);
    @memcpy(pkt[6..12], &main.lan_iface.mac);
    @memcpy(pkt[30..34], &fwd.lan_ip);
    util.writeU16Be(pkt[transport_start + 2 ..][0..2], fwd.lan_port);

    util.recomputeTransportChecksum(pkt, transport_start, len, protocol);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = util.computeChecksum(pkt[14..][0..ip_hdr_len]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

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

    const protocol = pkt[23];
    if (protocol != 6 and protocol != 17) return false;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const transport_start = 14 + ip_hdr_len;
    if (transport_start + 4 > len) return false;

    var src_ip: [4]u8 = undefined;
    @memcpy(&src_ip, pkt[26..30]);
    const src_port = util.readU16Be(pkt[transport_start..][0..2]);
    const proto: util.Protocol = if (protocol == 6) .tcp else .udp;

    for (&main.port_forwards) |*f| {
        if (!f.valid) continue;
        if (f.protocol != proto) continue;
        if (!util.eql(&f.lan_ip, &src_ip)) continue;
        if (f.lan_port != src_port) continue;

        // Match — rewrite src to router WAN IP:wan_port
        const gateway_mac = arp.lookup(&main.wan_iface.arp_table, main.wan_gateway) orelse {
            arp.sendRequest(.wan, main.wan_gateway);
            return false;
        };

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &main.wan_iface.mac);
        @memcpy(pkt[26..30], &main.wan_iface.ip);
        util.writeU16Be(pkt[transport_start..][0..2], f.wan_port);

        pkt[24] = 0;
        pkt[25] = 0;
        const ip_cs = util.computeChecksum(pkt[14..][0..ip_hdr_len]);
        pkt[24] = @truncate(ip_cs >> 8);
        pkt[25] = @truncate(ip_cs);

        util.recomputeTransportChecksum(pkt, transport_start, len, protocol);
        return true;
    }
    return false;
}
