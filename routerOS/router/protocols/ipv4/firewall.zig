const lib = @import("lib");
const router = @import("router");

const arp = router.protocols.arp;
const h = router.hal.headers;
const main = router.state;
const util = router.util;

const Seqlock = lib.sync.Seqlock;
const assert = util.assert;

pub const RULES_SIZE = 64;
pub const PORT_FWD_SIZE = 32;

pub const FirewallAction = enum { allow, block };

pub const FirewallRule = struct {
    seq: Seqlock = Seqlock.init(),
    valid: bool = false,
    action: FirewallAction = .block,
    src_ip: [4]u8 = .{ 0, 0, 0, 0 },
    src_mask: [4]u8 = .{ 0, 0, 0, 0 },
    protocol: u8 = 0,
    dst_port: u16 = 0,
};

pub const empty_rule = FirewallRule{};

pub const PortFwdSource = enum(u8) { manual = 0, upnp = 1, pcp = 2 };

pub const PortForward = struct {
    seq: Seqlock = Seqlock.init(),
    valid: bool = false,
    protocol: util.Protocol = .tcp,
    wan_port: u16 = 0,
    lan_ip: [4]u8 = .{ 0, 0, 0, 0 },
    lan_port: u16 = 0,
    lease_expiry_ns: u64 = 0, // 0 = permanent (manual), else monotonic deadline
    source: PortFwdSource = .manual,
};

pub const empty_fwd = PortForward{};

pub fn check(rules: *[RULES_SIZE]FirewallRule, src_ip: [4]u8, protocol: u8, dst_port: u16) FirewallAction {
    for (rules) |*r| {
        const gen = r.seq.readBeginNonblock();
        if (!r.valid) {
            if (!r.seq.readRetry(gen)) continue;
            continue;
        }
        const action = r.action;
        const r_src_ip = r.src_ip;
        const r_src_mask = r.src_mask;
        const r_protocol = r.protocol;
        const r_dst_port = r.dst_port;
        if (r.seq.readRetry(gen)) continue;

        const ip_match = (src_ip[0] & r_src_mask[0]) == (r_src_ip[0] & r_src_mask[0]) and
            (src_ip[1] & r_src_mask[1]) == (r_src_ip[1] & r_src_mask[1]) and
            (src_ip[2] & r_src_mask[2]) == (r_src_ip[2] & r_src_mask[2]) and
            (src_ip[3] & r_src_mask[3]) == (r_src_ip[3] & r_src_mask[3]);
        if (!ip_match) continue;
        if (r_protocol != 0 and r_protocol != protocol) continue;
        if (r_dst_port != 0 and r_dst_port != dst_port) continue;
        return action;
    }
    return .allow;
}

pub fn portFwdLookup(forwards: *[PORT_FWD_SIZE]PortForward, proto: util.Protocol, wan_port: u16) ?PortForward {
    for (forwards) |*f| {
        const gen = f.seq.readBeginNonblock();
        const valid = f.valid;
        const f_proto = f.protocol;
        const f_wan_port = f.wan_port;
        const f_lan_ip = f.lan_ip;
        const f_lan_port = f.lan_port;
        if (f.seq.readRetry(gen)) continue;

        if (valid and f_proto == proto and f_wan_port == wan_port) {
            return .{
                .valid = true,
                .protocol = f_proto,
                .wan_port = f_wan_port,
                .lan_ip = f_lan_ip,
                .lan_port = f_lan_port,
            };
        }
    }
    return null;
}

pub fn portFwdAdd(forwards: *[PORT_FWD_SIZE]PortForward, proto: util.Protocol, wan_port: u16, lip: [4]u8, lport: u16) bool {
    return portFwdAddLeased(forwards, proto, wan_port, lip, lport, 0, .manual);
}

pub fn portFwdAddLeased(forwards: *[PORT_FWD_SIZE]PortForward, proto: util.Protocol, wan_port: u16, lip: [4]u8, lport: u16, expiry_ns: u64, source: PortFwdSource) bool {
    for (forwards) |*f| {
        if (!f.valid) {
            f.seq.writeBegin();
            f.valid = true;
            f.protocol = proto;
            f.wan_port = wan_port;
            f.lan_ip = lip;
            f.lan_port = lport;
            f.lease_expiry_ns = expiry_ns;
            f.source = source;
            f.seq.writeEnd();
            return true;
        }
    }
    return false;
}

pub fn portFwdDelete(forwards: *[PORT_FWD_SIZE]PortForward, proto: util.Protocol, wan_port: u16) bool {
    for (forwards) |*f| {
        if (f.valid and f.protocol == proto and f.wan_port == wan_port) {
            f.seq.writeBegin();
            f.valid = false;
            f.lease_expiry_ns = 0;
            f.source = .manual;
            f.seq.writeEnd();
            return true;
        }
    }
    return false;
}

pub fn expireLeases(forwards: *[PORT_FWD_SIZE]PortForward, now_ns: u64) void {
    for (forwards) |*f| {
        if (f.valid and f.lease_expiry_ns != 0 and now_ns >= f.lease_expiry_ns) {
            f.seq.writeBegin();
            f.valid = false;
            f.lease_expiry_ns = 0;
            f.source = .manual;
            f.seq.writeEnd();
        }
    }
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
    _ = main.lan_iface.txSendLocal(pkt[0..len], .dataplane);
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
        const gen = f.seq.readBeginNonblock();
        const valid = f.valid;
        const f_proto = f.protocol;
        const f_lan_ip = f.lan_ip;
        const f_lan_port = f.lan_port;
        const f_wan_port = f.wan_port;
        if (f.seq.readRetry(gen)) continue;

        if (!valid) continue;
        if (f_proto != proto) continue;
        if (!util.eql(&f_lan_ip, &ip.src_ip)) continue;
        if (f_lan_port != udp.srcPort()) continue;

        // Match — rewrite src to router WAN IP:wan_port
        const gateway_mac = arp.lookup(&main.wan_iface.arp_table, main.wan_gateway) orelse {
            arp.sendRequest(.wan, main.wan_gateway);
            return false;
        };

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &main.wan_iface.mac);
        @memcpy(&ip.src_ip, &main.wan_iface.ip);
        udp.setSrcPort(f_wan_port);

        ip.computeAndSetChecksum(pkt);

        util.recomputeTransportChecksum(pkt, transport_start, len, ip.protocol);
        return true;
    }
    return false;
}
