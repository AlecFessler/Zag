const router = @import("router");

const h = router.net.headers;
const main = router.state;
const util = router.util;

pub const TABLE_SIZE = 128;
pub const STATIC_TABLE_SIZE = 32;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

pub const LEASE_DURATION_NS: u64 = 7200_000_000_000; // 7200 seconds

pub const DhcpLease = struct {
    mac: [6]u8,
    ip: [4]u8,
    valid: bool,
    timestamp_ns: u64,
};

pub const StaticLease = struct {
    mac: [6]u8,
    ip: [4]u8,
    valid: bool,
};

pub const empty = DhcpLease{ .mac = .{ 0, 0, 0, 0, 0, 0 }, .ip = .{ 0, 0, 0, 0 }, .valid = false, .timestamp_ns = 0 };
pub const empty_static = StaticLease{ .mac = .{ 0, 0, 0, 0, 0, 0 }, .ip = .{ 0, 0, 0, 0 }, .valid = false };

fn findLease(leases: []const DhcpLease, mac: [6]u8) ?[4]u8 {
    for (leases) |l| {
        if (l.valid and util.eql(&l.mac, &mac)) return l.ip;
    }
    return null;
}

fn allocateLease(mac: [6]u8) ?[4]u8 {
    // Check static leases first
    for (&main.dhcp_static_leases) |*s| {
        if (s.valid and util.eql(&s.mac, &mac)) return s.ip;
    }

    const now = util.now();
    // Renew existing lease
    for (&main.dhcp_leases) |*l| {
        if (l.valid and util.eql(&l.mac, &mac)) {
            l.timestamp_ns = now;
            return l.ip;
        }
    }
    // Allocate new lease, skipping IPs reserved by static leases
    for (&main.dhcp_leases) |*l| {
        if (!l.valid) {
            var candidate = main.dhcp_next_ip;
            var attempts: u16 = 0;
            while (attempts < 156) : (attempts += 1) { // 256 - 100 = 156 possible IPs
                if (!staticLeaseConflict(.{ 10, 1, 1, candidate })) break;
                candidate +%= 1;
                if (candidate < 100) candidate = 100;
            } else return null; // all IPs conflict with static leases

            l.ip = .{ 10, 1, 1, candidate };
            @memcpy(&l.mac, &mac);
            l.valid = true;
            l.timestamp_ns = now;
            main.dhcp_next_ip = candidate +% 1;
            if (main.dhcp_next_ip < 100) main.dhcp_next_ip = 100;
            return l.ip;
        }
    }
    return null;
}

fn staticLeaseConflict(ip: [4]u8) bool {
    for (&main.dhcp_static_leases) |*s| {
        if (s.valid and util.eql(&s.ip, &ip)) return true;
    }
    return false;
}

/// Expire leases that have exceeded their duration.
pub fn expireLeases() void {
    const now = util.now();
    for (&main.dhcp_leases) |*l| {
        if (l.valid and now -% l.timestamp_ns > LEASE_DURATION_NS) {
            l.valid = false;
        }
    }
}

pub fn handle(pkt: []const u8, len: u32) void {
    if (!main.has_lan) return;
    if (len < 282) return;

    const ip = h.Ipv4Header.parse(pkt[14..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;

    const udp = h.UdpHeader.parse(pkt[udp_start..]) orelse return;
    if (udp.srcPort() != 68 or udp.dstPort() != 67) return;

    const dhcp_start = udp_start + 8;
    if (dhcp_start + 240 > len) return;

    if (pkt[dhcp_start] != 1) return;

    var client_mac: [6]u8 = undefined;
    @memcpy(&client_mac, pkt[dhcp_start + 28 ..][0..6]);

    const magic_offset = dhcp_start + 236;
    if (pkt[magic_offset] != 0x63 or pkt[magic_offset + 1] != 0x82 or
        pkt[magic_offset + 2] != 0x53 or pkt[magic_offset + 3] != 0x63) return;

    var msg_type: u8 = 0;
    var opt_idx: u32 = magic_offset + 4;
    while (opt_idx + 1 < len) {
        const opt = pkt[opt_idx];
        if (opt == 255) break;
        if (opt == 0) {
            opt_idx += 1;
            continue;
        }
        const opt_len = pkt[opt_idx + 1];
        if (opt == 53 and opt_len >= 1) {
            msg_type = pkt[opt_idx + 2];
        }
        opt_idx += 2 + @as(u32, opt_len);
    }

    if (msg_type == DHCP_DISCOVER or msg_type == DHCP_REQUEST) {
        const offer_ip = allocateLease(client_mac) orelse return;
        const response_type: u8 = if (msg_type == DHCP_DISCOVER) DHCP_OFFER else DHCP_ACK;
        sendResponse(pkt[dhcp_start..], client_mac, offer_ip, response_type);
    }
}

fn sendResponse(request: []const u8, client_mac: [6]u8, offer_ip: [4]u8, msg_type: u8) void {
    var pkt: [600]u8 = undefined;
    @memset(&pkt, 0);

    const eth = h.EthernetHeader.parseMut(&pkt) orelse unreachable;
    @memset(&eth.dst_mac, 0xFF);
    @memcpy(&eth.src_mac, &main.lan_iface.mac);
    eth.setEtherType(h.EthernetHeader.IPv4);

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse unreachable;
    ip.ver_ihl = 0x45;
    ip.tos = 0x00;
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_UDP;
    @memcpy(&ip.src_ip, &main.lan_iface.ip);
    @memset(&ip.dst_ip, 0xFF);

    const udp_start: usize = 34;
    const udp = h.UdpHeader.parseMut(pkt[udp_start..]) orelse unreachable;
    udp.setSrcPort(67);
    udp.setDstPort(68);

    const dhcp_start: usize = udp_start + 8;
    pkt[dhcp_start] = 2;
    pkt[dhcp_start + 1] = 1;
    pkt[dhcp_start + 2] = 6;
    pkt[dhcp_start + 3] = 0;
    @memcpy(pkt[dhcp_start + 4 ..][0..4], request[4..8]);
    @memcpy(pkt[dhcp_start + 16 ..][0..4], &offer_ip);
    @memcpy(pkt[dhcp_start + 20 ..][0..4], &main.lan_iface.ip);
    @memcpy(pkt[dhcp_start + 28 ..][0..6], &client_mac);

    const magic: usize = dhcp_start + 236;
    pkt[magic] = 0x63;
    pkt[magic + 1] = 0x82;
    pkt[magic + 2] = 0x53;
    pkt[magic + 3] = 0x63;

    var opt: usize = magic + 4;
    pkt[opt] = 53;
    pkt[opt + 1] = 1;
    pkt[opt + 2] = msg_type;
    opt += 3;

    pkt[opt] = 1;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &main.lan_mask);
    opt += 6;

    pkt[opt] = 3;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &main.lan_iface.ip);
    opt += 6;

    pkt[opt] = 6;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &main.lan_iface.ip);
    opt += 6;

    pkt[opt] = 51;
    pkt[opt + 1] = 4;
    pkt[opt + 2] = 0;
    pkt[opt + 3] = 0;
    pkt[opt + 4] = 0x1C;
    pkt[opt + 5] = 0x20;
    opt += 6;

    pkt[opt] = 54;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &main.lan_iface.ip);
    opt += 6;

    pkt[opt] = 255;
    opt += 1;

    const total_dhcp = opt - dhcp_start;
    const udp_len: u16 = @truncate(8 + total_dhcp);
    udp.setLength(udp_len);

    const ip_total: u16 = @truncate(20 + udp_len);
    ip.setTotalLen(ip_total);

    ip.computeAndSetChecksum(&pkt);

    const total_len = 14 + ip_total;
    const send_len = if (total_len < 60) @as(usize, 60) else @as(usize, @intCast(total_len));
    _ = main.lan_iface.txSendLocal(pkt[0..send_len]);
}
