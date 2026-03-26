const router = @import("router");

const arp = router.net.arp;
const h = router.net.headers;
const main = router.state;
const util = router.util;

pub const RELAY_SIZE = 256;
pub const DNS_PORT: u16 = 53;

pub const DnsRelay = struct {
    valid: bool,
    client_ip: [4]u8,
    client_mac: [6]u8,
    client_port: u16,
    query_id: u16,
    relay_id: u16,
    timestamp_ns: u64,
};

pub const empty = DnsRelay{
    .valid = false,
    .client_ip = .{ 0, 0, 0, 0 },
    .client_mac = .{ 0, 0, 0, 0, 0, 0 },
    .client_port = 0,
    .query_id = 0,
    .relay_id = 0,
    .timestamp_ns = 0,
};

pub fn handleFromLan(pkt: []u8, len: u32) void {
    if (len < 34) return;

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;
    if (ip.protocol != h.Ipv4Header.PROTO_UDP) return;

    const udp = h.UdpHeader.parseMut(pkt[udp_start..]) orelse return;
    if (udp.dstPort() != DNS_PORT) return;

    const src_port = udp.srcPort();
    var client_ip: [4]u8 = undefined;
    @memcpy(&client_ip, &ip.src_ip);
    var client_mac: [6]u8 = undefined;
    @memcpy(&client_mac, pkt[6..12]);

    const dns_start = udp_start + 8;
    if (dns_start + 2 > len) return;
    const query_id = util.readU16Be(pkt[dns_start..][0..2]);

    const relay_id = main.next_dns_id;
    main.next_dns_id +%= 1;
    if (main.next_dns_id == 0) main.next_dns_id = 1;

    var slot: ?*DnsRelay = null;
    var oldest_idx: usize = 0;
    var oldest_ts: u64 = util.now();
    for (&main.dns_relays, 0..) |*r, i| {
        if (!r.valid) {
            slot = r;
            break;
        }
        if (r.timestamp_ns < oldest_ts) {
            oldest_ts = r.timestamp_ns;
            oldest_idx = i;
        }
    }
    if (slot == null) slot = &main.dns_relays[oldest_idx];

    slot.?.* = .{
        .valid = true,
        .client_ip = client_ip,
        .client_mac = client_mac,
        .client_port = src_port,
        .query_id = query_id,
        .relay_id = relay_id,
        .timestamp_ns = util.now(),
    };

    util.writeU16Be(pkt[dns_start..][0..2], relay_id);

    // Use WAN gateway MAC as next-hop (always known after boot ARP exchange)
    // rather than looking up the upstream DNS IP which may not be in ARP table
    const gateway_mac = arp.lookup(&main.wan_iface.arp_table, main.wan_gateway) orelse {
        arp.sendRequest(.wan, main.wan_gateway);
        return;
    };

    @memcpy(pkt[0..6], &gateway_mac);
    @memcpy(pkt[6..12], &main.wan_iface.mac);
    @memcpy(&ip.src_ip, &main.wan_iface.ip);
    @memcpy(&ip.dst_ip, &main.upstream_dns);

    udp.setSrcPort(relay_id);

    udp.zeroChecksum();

    ip.computeAndSetChecksum(pkt);

    main.wan_iface.stats.tx_packets += 1;
    main.wan_iface.stats.tx_bytes += len;
    _ = main.wan_iface.txSendLocal(pkt[0..len]);
}

pub fn handleFromWan(pkt: []u8, len: u32) void {
    if (!main.has_lan) return;
    if (len < 34) return;

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;
    if (ip.protocol != h.Ipv4Header.PROTO_UDP) return;

    const udp = h.UdpHeader.parseMut(pkt[udp_start..]) orelse return;
    if (udp.srcPort() != DNS_PORT) return;

    const dns_start = udp_start + 8;
    if (dns_start + 2 > len) return;
    const resp_id = util.readU16Be(pkt[dns_start..][0..2]);

    for (&main.dns_relays) |*r| {
        if (r.valid and r.relay_id == resp_id) {
            util.writeU16Be(pkt[dns_start..][0..2], r.query_id);

            @memcpy(pkt[0..6], &r.client_mac);
            @memcpy(pkt[6..12], &main.lan_iface.mac);
            @memcpy(&ip.src_ip, &main.lan_iface.ip);
            @memcpy(&ip.dst_ip, &r.client_ip);

            udp.setDstPort(r.client_port);
            udp.setSrcPort(DNS_PORT);

            udp.zeroChecksum();

            ip.computeAndSetChecksum(pkt);

            main.lan_iface.stats.tx_packets += 1;
            main.lan_iface.stats.tx_bytes += len;
            _ = main.lan_iface.txSendLocal(pkt[0..len]);

            r.valid = false;
            return;
        }
    }
}
