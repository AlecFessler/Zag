const std = @import("std");
const router = @import("router");

const firewall = router.protocols.ipv4.firewall;
const h = router.hal.headers;
const nat = router.protocols.ipv4.nat;
const state = router.state;
const util = router.util;

const harness = @import("harness.zig");

const Interface = state.Interface;

pub const PacketKind = enum {
    arp_request,
    arp_reply,
    icmp_echo_for_me,
    icmp_echo_forward,
    icmp_echo_reply_wan,
    tcp_syn_lan_to_wan,
    tcp_syn_ack_wan,
    tcp_ack,
    tcp_fin,
    tcp_rst,
    udp_lan_to_wan,
    udp_wan_to_lan,
    udp_dns_query,
    ipv4_ttl1_forward,
    ipv4_fragment_first,
    ipv4_broadcast,
    ipv6_packet,
    malformed_truncated,
    malformed_bad_ihl,
    malformed_bad_totlen,
    random_ethertype,
    nat_return,
    tcp_syn_with_options,
    dhcp_discover,
    dns_response_wan,
    tcp_to_port_80,
    udp_to_unhandled_port,
    pcp_map_request,
    upnp_ssdp_msearch,
};

pub const GeneratedPacket = struct {
    buf: [2048]u8 = undefined,
    len: u32 = 0,
    interface: Interface = .lan,
    kind: PacketKind = .arp_request,
    src_ip: [4]u8 = .{ 0, 0, 0, 0 },
    dst_ip: [4]u8 = .{ 0, 0, 0, 0 },
    src_port: u16 = 0,
    dst_port: u16 = 0,
    protocol: u8 = 0,
    ttl: u8 = 64,
    is_mutated: bool = false,
    icmp_id: u16 = 0,
    icmp_seq: u16 = 0,
    tcp_flags: u8 = 0,
    src_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
};

// Weight table: kind, cumulative_weight
// Higher weight = more frequent selection
const WeightEntry = struct { kind: PacketKind, weight: u32 };
const weights = [_]WeightEntry{
    .{ .kind = .tcp_syn_lan_to_wan, .weight = 15 },
    .{ .kind = .udp_lan_to_wan, .weight = 15 },
    .{ .kind = .nat_return, .weight = 12 },
    .{ .kind = .tcp_syn_ack_wan, .weight = 10 },
    .{ .kind = .tcp_ack, .weight = 8 },
    .{ .kind = .tcp_fin, .weight = 5 },
    .{ .kind = .tcp_rst, .weight = 3 },
    .{ .kind = .icmp_echo_for_me, .weight = 8 },
    .{ .kind = .icmp_echo_forward, .weight = 5 },
    .{ .kind = .icmp_echo_reply_wan, .weight = 3 },
    .{ .kind = .udp_wan_to_lan, .weight = 5 },
    .{ .kind = .udp_dns_query, .weight = 5 },
    .{ .kind = .arp_request, .weight = 5 },
    .{ .kind = .arp_reply, .weight = 3 },
    .{ .kind = .ipv4_ttl1_forward, .weight = 3 },
    .{ .kind = .ipv4_fragment_first, .weight = 2 },
    .{ .kind = .ipv4_broadcast, .weight = 2 },
    .{ .kind = .ipv6_packet, .weight = 3 },
    .{ .kind = .malformed_truncated, .weight = 4 },
    .{ .kind = .malformed_bad_ihl, .weight = 3 },
    .{ .kind = .malformed_bad_totlen, .weight = 3 },
    .{ .kind = .random_ethertype, .weight = 2 },
    .{ .kind = .tcp_syn_with_options, .weight = 8 },
    .{ .kind = .dhcp_discover, .weight = 5 },
    .{ .kind = .dns_response_wan, .weight = 5 },
    .{ .kind = .tcp_to_port_80, .weight = 5 },
    .{ .kind = .udp_to_unhandled_port, .weight = 5 },
    .{ .kind = .pcp_map_request, .weight = 5 },
    .{ .kind = .upnp_ssdp_msearch, .weight = 5 },
};

const total_weight: u32 = blk: {
    var sum: u32 = 0;
    for (weights) |w| sum += w.weight;
    break :blk sum;
};

pub fn generateRandom(random: std.Random) GeneratedPacket {
    const roll = random.intRangeLessThan(u32, 0, total_weight);
    var cumulative: u32 = 0;
    for (weights) |w| {
        cumulative += w.weight;
        if (roll < cumulative) {
            return generate(random, w.kind);
        }
    }
    // Fallback (should not reach)
    return generate(random, .tcp_syn_lan_to_wan);
}

pub fn generate(random: std.Random, kind: PacketKind) GeneratedPacket {
    return switch (kind) {
        .arp_request => generateArpRequest(random),
        .arp_reply => generateArpReply(random),
        .icmp_echo_for_me => generateIcmpEchoForMe(random),
        .icmp_echo_forward => generateIcmpEchoForward(random),
        .icmp_echo_reply_wan => generateIcmpEchoReplyWan(random),
        .tcp_syn_lan_to_wan => generateTcpLanToWan(random, 0x02), // SYN
        .tcp_syn_ack_wan => generateTcpSynAckWan(random),
        .tcp_ack => generateTcpLanToWan(random, 0x10), // ACK
        .tcp_fin => generateTcpLanToWan(random, 0x11), // FIN+ACK
        .tcp_rst => generateTcpLanToWan(random, 0x04), // RST
        .udp_lan_to_wan => generateUdpLanToWan(random),
        .udp_wan_to_lan => generateUdpWanToLan(random),
        .udp_dns_query => generateUdpDnsQuery(random),
        .ipv4_ttl1_forward => generateTtl1Forward(random),
        .ipv4_fragment_first => generateFragment(random),
        .ipv4_broadcast => generateBroadcast(random),
        .ipv6_packet => generateIpv6(random),
        .malformed_truncated => generateTruncated(random),
        .malformed_bad_ihl => generateBadIhl(random),
        .malformed_bad_totlen => generateBadTotalLen(random),
        .random_ethertype => generateRandomEthertype(random),
        .nat_return => generateNatReturn(random),
        .tcp_syn_with_options => generateTcpSynWithOptions(random),
        .dhcp_discover => generateDhcpDiscover(random),
        .dns_response_wan => generateDnsResponseWan(random),
        .tcp_to_port_80 => generateTcpToPort80(random),
        .udp_to_unhandled_port => generateUdpToUnhandledPort(random),
        .pcp_map_request => generatePcpMapRequest(random),
        .upnp_ssdp_msearch => generateSsdpMsearch(random),
    };
}

// ── Helpers ──────────────────────────────────────────────────────────────

const LanHost = struct { ip: [4]u8, mac: [6]u8 };

fn randomLanHost(random: std.Random) LanHost {
    const idx = random.intRangeLessThan(usize, 0, harness.lan_hosts.len);
    const host = harness.lan_hosts[idx];
    return .{ .ip = host.ip, .mac = host.mac };
}

fn randomExternalIp(random: std.Random) [4]u8 {
    return .{
        random.intRangeAtMost(u8, 1, 223),
        random.int(u8),
        random.int(u8),
        random.intRangeAtMost(u8, 1, 254),
    };
}

pub fn writeEthernet(buf: *[2048]u8, dst: [6]u8, src: [6]u8, ethertype: u16) void {
    @memcpy(buf[0..6], &dst);
    @memcpy(buf[6..12], &src);
    buf[12] = @truncate(ethertype >> 8);
    buf[13] = @truncate(ethertype);
}

pub fn writeIpv4(buf: *[2048]u8, src: [4]u8, dst: [4]u8, protocol: u8, ttl: u8, total_len: u16) void {
    buf[14] = 0x45; // version 4, IHL 5
    buf[15] = 0x00; // DSCP/ECN
    buf[16] = @truncate(total_len >> 8);
    buf[17] = @truncate(total_len);
    buf[18] = 0x00; // identification
    buf[19] = 0x00;
    buf[20] = 0x40; // don't fragment
    buf[21] = 0x00;
    buf[22] = ttl;
    buf[23] = protocol;
    buf[24] = 0; // checksum (computed below)
    buf[25] = 0;
    @memcpy(buf[26..30], &src);
    @memcpy(buf[30..34], &dst);

    // Compute IP header checksum
    const ip_hdr = buf[14..34];
    var sum: u32 = 0;
    var i: usize = 0;
    while (i < 20) : (i += 2) {
        sum += @as(u32, ip_hdr[i]) << 8 | @as(u32, ip_hdr[i + 1]);
    }
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    const checksum: u16 = @truncate(~sum);
    buf[24] = @truncate(checksum >> 8);
    buf[25] = @truncate(checksum);
}

pub fn writeTcp(buf: *[2048]u8, offset: usize, src_port: u16, dst_port: u16, flags: u8) void {
    buf[offset + 0] = @truncate(src_port >> 8);
    buf[offset + 1] = @truncate(src_port);
    buf[offset + 2] = @truncate(dst_port >> 8);
    buf[offset + 3] = @truncate(dst_port);
    // seq number
    buf[offset + 4] = 0;
    buf[offset + 5] = 0;
    buf[offset + 6] = 0;
    buf[offset + 7] = 1;
    // ack number
    buf[offset + 8] = 0;
    buf[offset + 9] = 0;
    buf[offset + 10] = 0;
    buf[offset + 11] = 0;
    // data offset (5 words = 20 bytes) + reserved
    buf[offset + 12] = 0x50;
    buf[offset + 13] = flags;
    // window
    buf[offset + 14] = 0xFF;
    buf[offset + 15] = 0xFF;
    // checksum (zero for now — router recomputes on NAT)
    buf[offset + 16] = 0;
    buf[offset + 17] = 0;
    // urgent pointer
    buf[offset + 18] = 0;
    buf[offset + 19] = 0;
}

pub fn writeUdp(buf: *[2048]u8, offset: usize, src_port: u16, dst_port: u16, udp_len: u16) void {
    buf[offset + 0] = @truncate(src_port >> 8);
    buf[offset + 1] = @truncate(src_port);
    buf[offset + 2] = @truncate(dst_port >> 8);
    buf[offset + 3] = @truncate(dst_port);
    buf[offset + 4] = @truncate(udp_len >> 8);
    buf[offset + 5] = @truncate(udp_len);
    buf[offset + 6] = 0; // checksum
    buf[offset + 7] = 0;
}

fn writeIcmpEcho(buf: *[2048]u8, offset: usize, typ: u8, id: u16, seq: u16) void {
    buf[offset + 0] = typ; // type
    buf[offset + 1] = 0; // code
    buf[offset + 2] = 0; // checksum (computed below)
    buf[offset + 3] = 0;
    buf[offset + 4] = @truncate(id >> 8);
    buf[offset + 5] = @truncate(id);
    buf[offset + 6] = @truncate(seq >> 8);
    buf[offset + 7] = @truncate(seq);

    // Compute ICMP checksum over the ICMP portion
    var sum: u32 = 0;
    var i: usize = offset;
    while (i + 1 < offset + 8) : (i += 2) {
        sum += @as(u32, buf[i]) << 8 | @as(u32, buf[i + 1]);
    }
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    const cksum: u16 = @truncate(~sum);
    buf[offset + 2] = @truncate(cksum >> 8);
    buf[offset + 3] = @truncate(cksum);
}

// ── Generators ───────────────────────────────────────────────────────────

fn generateArpRequest(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .arp_request, .interface = .lan };
    const host = randomLanHost(random);
    pkt.src_ip = host.ip;
    pkt.src_mac = host.mac;
    pkt.dst_ip = harness.LAN_IP;

    @memset(&pkt.buf, 0);
    // Ethernet: broadcast dest, host source, ARP ethertype
    writeEthernet(&pkt.buf, .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, host.mac, h.EthernetHeader.ARP);

    // ARP header
    pkt.buf[14] = 0x00;
    pkt.buf[15] = 0x01; // hardware type: Ethernet
    pkt.buf[16] = 0x08;
    pkt.buf[17] = 0x00; // protocol type: IPv4
    pkt.buf[18] = 6; // hardware size
    pkt.buf[19] = 4; // protocol size
    pkt.buf[20] = 0x00;
    pkt.buf[21] = 0x01; // opcode: request
    @memcpy(pkt.buf[22..28], &host.mac); // sender MAC
    @memcpy(pkt.buf[28..32], &host.ip); // sender IP
    @memset(pkt.buf[32..38], 0); // target MAC (unknown)
    @memcpy(pkt.buf[38..42], &harness.LAN_IP); // target IP

    pkt.len = 42;
    return pkt;
}

fn generateArpReply(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .arp_reply, .interface = .lan };
    const host = randomLanHost(random);
    pkt.src_mac = host.mac;
    pkt.src_ip = host.ip;
    pkt.dst_ip = harness.LAN_IP;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.ARP);

    pkt.buf[14] = 0x00;
    pkt.buf[15] = 0x01;
    pkt.buf[16] = 0x08;
    pkt.buf[17] = 0x00;
    pkt.buf[18] = 6;
    pkt.buf[19] = 4;
    pkt.buf[20] = 0x00;
    pkt.buf[21] = 0x02; // opcode: reply
    @memcpy(pkt.buf[22..28], &host.mac);
    @memcpy(pkt.buf[28..32], &host.ip);
    @memcpy(pkt.buf[32..38], &harness.LAN_MAC);
    @memcpy(pkt.buf[38..42], &harness.LAN_IP);

    pkt.len = 42;
    return pkt;
}

fn generateIcmpEchoForMe(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .icmp_echo_for_me, .protocol = 1 };
    const host = randomLanHost(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = harness.LAN_IP;
    pkt.interface = .lan;
    pkt.src_mac = host.mac;
    pkt.icmp_id = random.int(u16);
    pkt.icmp_seq = random.int(u16);

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, harness.LAN_IP, 1, 64, 28);
    writeIcmpEcho(&pkt.buf, 34, 8, pkt.icmp_id, pkt.icmp_seq);

    pkt.len = 42;
    return pkt;
}

fn generateIcmpEchoForward(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .icmp_echo_forward, .protocol = 1 };
    const host = randomLanHost(random);
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = ext_ip;
    pkt.interface = .lan;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, ext_ip, 1, 64, 28);
    writeIcmpEcho(&pkt.buf, 34, 8, random.int(u16), random.int(u16));

    pkt.len = 42;
    return pkt;
}

fn generateIcmpEchoReplyWan(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .icmp_echo_reply_wan, .protocol = 1 };
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = ext_ip;
    pkt.dst_ip = harness.WAN_IP;
    pkt.interface = .wan;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.WAN_MAC, harness.WAN_GATEWAY_MAC, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, ext_ip, harness.WAN_IP, 1, 64, 28);
    writeIcmpEcho(&pkt.buf, 34, 0, random.int(u16), random.int(u16)); // type 0 = echo reply

    pkt.len = 42;
    return pkt;
}

fn generateTcpLanToWan(random: std.Random, flags: u8) GeneratedPacket {
    const kind: PacketKind = switch (flags) {
        0x02 => .tcp_syn_lan_to_wan,
        0x10 => .tcp_ack,
        0x11 => .tcp_fin,
        0x04 => .tcp_rst,
        else => .tcp_ack,
    };
    var pkt = GeneratedPacket{ .kind = kind, .protocol = 6, .interface = .lan };
    const host = randomLanHost(random);
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = ext_ip;
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = random.intRangeAtMost(u16, 1, 65535);
    pkt.tcp_flags = flags;
    pkt.src_mac = host.mac;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, ext_ip, 6, 64, 40);
    writeTcp(&pkt.buf, 34, pkt.src_port, pkt.dst_port, flags);

    pkt.len = 54;
    return pkt;
}

fn generateTcpSynAckWan(random: std.Random) GeneratedPacket {
    // Try to find an active NAT entry to respond to
    var pkt = GeneratedPacket{ .kind = .tcp_syn_ack_wan, .protocol = 6, .interface = .wan };

    // Scan NAT table for an active TCP entry
    for (&state.nat_table) |*entry| {
        if (@atomicLoad(u8, &entry.state, .acquire) == @intFromEnum(nat.State.active) and
            entry.protocol == 6)
        {
            pkt.src_ip = entry.dst_ip;
            pkt.dst_ip = harness.WAN_IP;
            pkt.src_port = entry.dst_port;
            pkt.dst_port = entry.wan_port;

            @memset(&pkt.buf, 0);
            writeEthernet(&pkt.buf, harness.WAN_MAC, harness.WAN_GATEWAY_MAC, h.EthernetHeader.IPv4);
            writeIpv4(&pkt.buf, entry.dst_ip, harness.WAN_IP, 6, 64, 40);
            writeTcp(&pkt.buf, 34, entry.dst_port, entry.wan_port, 0x12); // SYN+ACK

            pkt.len = 54;
            return pkt;
        }
    }

    // No matching NAT entry — generate random WAN TCP (will be dropped)
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = ext_ip;
    pkt.dst_ip = harness.WAN_IP;
    pkt.src_port = random.intRangeAtMost(u16, 1, 65535);
    pkt.dst_port = random.intRangeAtMost(u16, 1, 65535);

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.WAN_MAC, harness.WAN_GATEWAY_MAC, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, ext_ip, harness.WAN_IP, 6, 64, 40);
    writeTcp(&pkt.buf, 34, pkt.src_port, pkt.dst_port, 0x12);

    pkt.len = 54;
    return pkt;
}

fn generateUdpLanToWan(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .udp_lan_to_wan, .protocol = 17, .interface = .lan };
    const host = randomLanHost(random);
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = ext_ip;
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = random.intRangeAtMost(u16, 1, 65535);

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, ext_ip, 17, 64, 28); // 20 IP + 8 UDP
    writeUdp(&pkt.buf, 34, pkt.src_port, pkt.dst_port, 8);

    pkt.len = 42;
    return pkt;
}

fn generateUdpWanToLan(random: std.Random) GeneratedPacket {
    // Like TCP SYN-ACK, try to match an active NAT entry
    var pkt = GeneratedPacket{ .kind = .udp_wan_to_lan, .protocol = 17, .interface = .wan };

    for (&state.nat_table) |*entry| {
        if (@atomicLoad(u8, &entry.state, .acquire) == @intFromEnum(nat.State.active) and
            entry.protocol == 17)
        {
            pkt.src_ip = entry.dst_ip;
            pkt.dst_ip = harness.WAN_IP;
            pkt.src_port = entry.dst_port;
            pkt.dst_port = entry.wan_port;

            @memset(&pkt.buf, 0);
            writeEthernet(&pkt.buf, harness.WAN_MAC, harness.WAN_GATEWAY_MAC, h.EthernetHeader.IPv4);
            writeIpv4(&pkt.buf, entry.dst_ip, harness.WAN_IP, 17, 64, 28);
            writeUdp(&pkt.buf, 34, entry.dst_port, entry.wan_port, 8);

            pkt.len = 42;
            return pkt;
        }
    }

    // No matching entry — random WAN UDP
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = ext_ip;
    pkt.dst_ip = harness.WAN_IP;
    pkt.src_port = random.intRangeAtMost(u16, 1, 65535);
    pkt.dst_port = random.intRangeAtMost(u16, 1, 65535);

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.WAN_MAC, harness.WAN_GATEWAY_MAC, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, ext_ip, harness.WAN_IP, 17, 64, 28);
    writeUdp(&pkt.buf, 34, pkt.src_port, pkt.dst_port, 8);

    pkt.len = 42;
    return pkt;
}

fn generateUdpDnsQuery(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .udp_dns_query, .protocol = 17, .interface = .lan };
    const host = randomLanHost(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = harness.LAN_IP;
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = 53;

    // Build a real question section with random domain labels
    const labels = [_][]const u8{ "a", "bb", "ccc", "test", "example" };
    const tlds = [_][]const u8{ "com", "net", "org" };
    const label = labels[random.intRangeLessThan(usize, 0, labels.len)];
    const tld = tlds[random.intRangeLessThan(usize, 0, tlds.len)];

    var qsection: [32]u8 = undefined;
    var qlen: usize = 0;
    qsection[qlen] = @intCast(label.len);
    qlen += 1;
    @memcpy(qsection[qlen..][0..label.len], label);
    qlen += label.len;
    qsection[qlen] = @intCast(tld.len);
    qlen += 1;
    @memcpy(qsection[qlen..][0..tld.len], tld);
    qlen += tld.len;
    qsection[qlen] = 0; // null terminator
    qlen += 1;
    qsection[qlen] = 0;
    qsection[qlen + 1] = 1; // QTYPE = A
    qlen += 2;
    qsection[qlen] = 0;
    qsection[qlen + 1] = 1; // QCLASS = IN
    qlen += 2;

    const payload_len: u16 = @intCast(12 + qlen);
    const udp_len: u16 = 8 + payload_len;
    const ip_total: u16 = 20 + udp_len;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, harness.LAN_IP, 17, 64, ip_total);
    writeUdp(&pkt.buf, 34, pkt.src_port, 53, udp_len);

    // DNS header
    pkt.buf[42] = random.int(u8); // transaction ID
    pkt.buf[43] = random.int(u8);
    pkt.buf[44] = 0x01; // flags: standard query, recursion desired
    pkt.buf[45] = 0x00;
    pkt.buf[46] = 0x00;
    pkt.buf[47] = 0x01; // QDCOUNT = 1

    // Question section
    @memcpy(pkt.buf[54..][0..qlen], qsection[0..qlen]);

    pkt.len = 14 + @as(u32, ip_total);
    return pkt;
}

fn generateTtl1Forward(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .ipv4_ttl1_forward, .protocol = 6, .interface = .lan };
    const host = randomLanHost(random);
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = ext_ip;
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = random.intRangeAtMost(u16, 1, 65535);

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, ext_ip, 6, 1, 40); // TTL = 1!
    writeTcp(&pkt.buf, 34, pkt.src_port, pkt.dst_port, 0x02);

    pkt.len = 54;
    return pkt;
}

fn generateFragment(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .ipv4_fragment_first, .protocol = 6, .interface = .lan };
    const host = randomLanHost(random);
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = ext_ip;
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = random.intRangeAtMost(u16, 1, 65535);

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, ext_ip, 6, 64, 40);

    // Set MF (more fragments) flag and IP identification
    pkt.buf[20] = 0x20; // MF flag set, fragment offset 0
    pkt.buf[21] = 0x00;
    pkt.buf[18] = random.int(u8); // IP ID
    pkt.buf[19] = random.int(u8);

    // Re-compute IP checksum
    pkt.buf[24] = 0;
    pkt.buf[25] = 0;
    var sum: u32 = 0;
    var i: usize = 14;
    while (i < 34) : (i += 2) {
        sum += @as(u32, pkt.buf[i]) << 8 | @as(u32, pkt.buf[i + 1]);
    }
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    const cksum: u16 = @truncate(~sum);
    pkt.buf[24] = @truncate(cksum >> 8);
    pkt.buf[25] = @truncate(cksum);

    writeTcp(&pkt.buf, 34, pkt.src_port, pkt.dst_port, 0x02);

    pkt.len = 54;
    return pkt;
}

fn generateBroadcast(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .ipv4_broadcast, .protocol = 17, .interface = .lan };
    const host = randomLanHost(random);
    pkt.src_ip = host.ip;

    // Randomly pick broadcast type
    if (random.boolean()) {
        pkt.dst_ip = .{ 255, 255, 255, 255 };
    } else {
        pkt.dst_ip = state.lan_broadcast;
    }

    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = random.intRangeAtMost(u16, 1, 65535);

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, pkt.dst_ip, 17, 64, 28);
    writeUdp(&pkt.buf, 34, pkt.src_port, pkt.dst_port, 8);

    pkt.len = 42;
    return pkt;
}

fn generateIpv6(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .ipv6_packet, .interface = .lan };

    @memset(&pkt.buf, 0);
    const host = randomLanHost(random);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv6);

    // IPv6 header (40 bytes)
    pkt.buf[14] = 0x60; // version 6
    pkt.buf[15] = 0x00;
    pkt.buf[16] = 0x00;
    pkt.buf[17] = 0x00;
    pkt.buf[18] = 0x00; // payload length
    pkt.buf[19] = 0x08; // 8 bytes payload
    pkt.buf[20] = 58; // next header: ICMPv6
    pkt.buf[21] = 64; // hop limit

    // Source: link-local (fe80::random)
    pkt.buf[22] = 0xfe;
    pkt.buf[23] = 0x80;
    pkt.buf[36] = random.int(u8);
    pkt.buf[37] = random.int(u8);

    // Dest: all-nodes multicast ff02::1
    pkt.buf[38] = 0xff;
    pkt.buf[39] = 0x02;
    pkt.buf[53] = 0x01;

    // ICMPv6 echo request
    pkt.buf[54] = 128; // type: echo request
    pkt.buf[55] = 0; // code
    // checksum left as 0 for now

    pkt.len = 62;
    return pkt;
}

fn generateTruncated(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .malformed_truncated, .interface = if (random.boolean()) .lan else .wan };

    @memset(&pkt.buf, 0);
    // Write a valid-looking Ethernet+IP start but truncate
    const host = randomLanHost(random);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    // Set some IP fields but keep len short
    pkt.buf[14] = 0x45;

    // Truncate to somewhere between 14 and 33 bytes (incomplete IP header or no transport)
    pkt.len = random.intRangeAtMost(u32, 14, 33);
    return pkt;
}

fn generateBadIhl(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .malformed_bad_ihl, .protocol = 6, .interface = .lan };
    const host = randomLanHost(random);
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = ext_ip;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, ext_ip, 6, 64, 40);

    // Corrupt IHL field: set to 0, 1, 2, 3 or 15
    const bad_ihl: u8 = switch (random.intRangeLessThan(u3, 0, 5)) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        else => 15,
    };
    pkt.buf[14] = (4 << 4) | bad_ihl; // version 4, bad IHL

    pkt.len = 54;
    return pkt;
}

fn generateBadTotalLen(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .malformed_bad_totlen, .protocol = 6, .interface = .lan };
    const host = randomLanHost(random);
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = ext_ip;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);

    // Write IP header with mismatched total_len
    const bad_totlen: u16 = if (random.boolean())
        random.intRangeAtMost(u16, 0, 19) // too small
    else
        random.intRangeAtMost(u16, 1500, 65535); // too large

    writeIpv4(&pkt.buf, host.ip, ext_ip, 6, 64, bad_totlen);
    writeTcp(&pkt.buf, 34, random.int(u16), random.int(u16), 0x02);

    pkt.len = 54; // actual buffer is 54 bytes regardless of total_len
    return pkt;
}

fn generateRandomEthertype(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{ .kind = .random_ethertype, .interface = if (random.boolean()) .lan else .wan };

    @memset(&pkt.buf, 0);
    const src_mac = if (pkt.interface == .lan) harness.lan_hosts[0].mac else harness.WAN_GATEWAY_MAC;
    const dst_mac = if (pkt.interface == .lan) harness.LAN_MAC else harness.WAN_MAC;

    // Random ethertype that isn't ARP, IPv4, or IPv6
    var ethertype: u16 = random.int(u16);
    while (ethertype == h.EthernetHeader.ARP or
        ethertype == h.EthernetHeader.IPv4 or
        ethertype == h.EthernetHeader.IPv6)
    {
        ethertype = random.int(u16);
    }

    writeEthernet(&pkt.buf, dst_mac, src_mac, ethertype);
    // Random payload
    for (pkt.buf[14..64]) |*b| b.* = random.int(u8);

    pkt.len = 64;
    return pkt;
}

fn generateNatReturn(random: std.Random) GeneratedPacket {
    // Scan NAT table for any active entry and generate matching WAN inbound
    for (&state.nat_table) |*entry| {
        if (@atomicLoad(u8, &entry.state, .acquire) == @intFromEnum(nat.State.active)) {
            var pkt = GeneratedPacket{
                .kind = .nat_return,
                .protocol = entry.protocol,
                .interface = .wan,
                .src_ip = entry.dst_ip,
                .dst_ip = harness.WAN_IP,
                .src_port = entry.dst_port,
                .dst_port = entry.wan_port,
            };

            @memset(&pkt.buf, 0);
            writeEthernet(&pkt.buf, harness.WAN_MAC, harness.WAN_GATEWAY_MAC, h.EthernetHeader.IPv4);

            if (entry.protocol == 6) { // TCP
                writeIpv4(&pkt.buf, entry.dst_ip, harness.WAN_IP, 6, 64, 40);
                writeTcp(&pkt.buf, 34, entry.dst_port, entry.wan_port, 0x10); // ACK
                pkt.len = 54;
            } else if (entry.protocol == 17) { // UDP
                writeIpv4(&pkt.buf, entry.dst_ip, harness.WAN_IP, 17, 64, 28);
                writeUdp(&pkt.buf, 34, entry.dst_port, entry.wan_port, 8);
                pkt.len = 42;
            } else { // ICMP
                writeIpv4(&pkt.buf, entry.dst_ip, harness.WAN_IP, 1, 64, 28);
                writeIcmpEcho(&pkt.buf, 34, 0, entry.wan_port, 1); // echo reply, id=wan_port
                pkt.len = 42;
            }

            return pkt;
        }
    }

    // No active NAT entries — fall back to random UDP LAN->WAN to create one
    return generateUdpLanToWan(random);
}

// ── New generators (v4) ──────────────────────────────────────────────

fn generateTcpSynWithOptions(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{
        .kind = .tcp_syn_with_options,
        .protocol = 6,
        .interface = .lan,
        .tcp_flags = 0x02,
    };
    const host = randomLanHost(random);
    const ext_ip = randomExternalIp(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = ext_ip;
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = random.intRangeAtMost(u16, 1, 65535);
    pkt.src_mac = host.mac;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    // IP total_len = 20 + 24 (TCP with 4 bytes options) = 44
    writeIpv4(&pkt.buf, host.ip, ext_ip, 6, 64, 44);
    writeTcp(&pkt.buf, 34, pkt.src_port, pkt.dst_port, 0x02); // SYN

    // Set TCP data offset = 6 (24 bytes = 20 header + 4 options)
    pkt.buf[46] = 0x60;

    // Write TCP options based on random choice
    const opt_choice = random.intRangeLessThan(u8, 0, 10);
    switch (opt_choice) {
        0 => { // MSS=1460 (should NOT be clamped)
            pkt.buf[54] = 2; pkt.buf[55] = 4;
            pkt.buf[56] = 0x05; pkt.buf[57] = 0xB4; // 1460
        },
        1 => { // MSS=9000 (should be clamped to 1460)
            pkt.buf[54] = 2; pkt.buf[55] = 4;
            pkt.buf[56] = 0x23; pkt.buf[57] = 0x28; // 9000
        },
        2 => { // MSS=1461 (edge case)
            pkt.buf[54] = 2; pkt.buf[55] = 4;
            pkt.buf[56] = 0x05; pkt.buf[57] = 0xB5; // 1461
        },
        3 => { // MSS=0
            pkt.buf[54] = 2; pkt.buf[55] = 4;
            pkt.buf[56] = 0x00; pkt.buf[57] = 0x00;
        },
        4 => { // MSS=65535
            pkt.buf[54] = 2; pkt.buf[55] = 4;
            pkt.buf[56] = 0xFF; pkt.buf[57] = 0xFF;
        },
        5 => { // NOP + MSS=8000 (NOP padding)
            pkt.buf[54] = 1; // NOP
            pkt.buf[55] = 2; pkt.buf[56] = 4;
            pkt.buf[57] = 0x1F; // 8000 = 0x1F40, but only 1 byte left
            // This is malformed (MSS split across option boundary)
        },
        6 => { // Kind=0 (end of options) before MSS
            pkt.buf[54] = 0; // end-of-options
        },
        7 => { // Kind=2 len=3 (wrong length)
            pkt.buf[54] = 2; pkt.buf[55] = 3;
            pkt.buf[56] = 0x05; pkt.buf[57] = 0xB4;
        },
        8 => { // Kind=2 len=0 (should break loop)
            pkt.buf[54] = 2; pkt.buf[55] = 0;
        },
        9 => { // Kind=2 len=4 with MSS=1500
            pkt.buf[54] = 2; pkt.buf[55] = 4;
            pkt.buf[56] = 0x05; pkt.buf[57] = 0xDC; // 1500
        },
        else => {},
    }

    pkt.len = 58; // 14 + 44
    return pkt;
}

fn generateDhcpDiscover(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{
        .kind = .dhcp_discover,
        .protocol = 17,
        .interface = .lan,
        .dst_port = 67,
        .src_port = 68,
    };

    // Use a random MAC (not necessarily from pre-seeded hosts)
    var client_mac: [6]u8 = undefined;
    for (&client_mac) |*b| b.* = random.int(u8);
    client_mac[0] = client_mac[0] & 0xFE | 0x02; // locally administered, unicast

    pkt.src_ip = .{ 0, 0, 0, 0 };
    pkt.dst_ip = .{ 255, 255, 255, 255 };
    pkt.src_mac = client_mac;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, client_mac, h.EthernetHeader.IPv4);

    // IP header: src=0.0.0.0, dst=255.255.255.255
    const udp_payload_len: u16 = 244; // DHCP minimum (236 fixed + 4 magic + 3 option + 1 end)
    const udp_len: u16 = 8 + udp_payload_len;
    const ip_total: u16 = 20 + udp_len;
    writeIpv4(&pkt.buf, .{ 0, 0, 0, 0 }, .{ 255, 255, 255, 255 }, 17, 64, ip_total);
    writeUdp(&pkt.buf, 34, 68, 67, udp_len);

    const dhcp_start: usize = 42;
    pkt.buf[dhcp_start] = 1; // op: BOOTREQUEST
    pkt.buf[dhcp_start + 1] = 1; // htype: Ethernet
    pkt.buf[dhcp_start + 2] = 6; // hlen: 6
    // xid (random)
    pkt.buf[dhcp_start + 4] = random.int(u8);
    pkt.buf[dhcp_start + 5] = random.int(u8);
    pkt.buf[dhcp_start + 6] = random.int(u8);
    pkt.buf[dhcp_start + 7] = random.int(u8);

    // Client MAC at dhcp+28
    @memcpy(pkt.buf[dhcp_start + 28 ..][0..6], &client_mac);

    // Magic cookie at dhcp+236
    const magic = dhcp_start + 236;
    pkt.buf[magic] = 0x63;
    pkt.buf[magic + 1] = 0x82;
    pkt.buf[magic + 2] = 0x53;
    pkt.buf[magic + 3] = 0x63;

    // Options
    var opt = magic + 4;
    pkt.buf[opt] = 53; // DHCP Message Type
    pkt.buf[opt + 1] = 1; // length
    pkt.buf[opt + 2] = if (random.boolean()) 1 else 3; // DISCOVER or REQUEST
    opt += 3;
    pkt.buf[opt] = 255; // End

    pkt.len = @intCast(14 + @as(u32, ip_total));
    return pkt;
}

fn generateDnsResponseWan(random: std.Random) GeneratedPacket {
    // Scan dns_relays for a valid entry to craft a matching response
    for (&state.dns_relays) |*r| {
        if (!r.valid) continue;

        var pkt = GeneratedPacket{
            .kind = .dns_response_wan,
            .protocol = 17,
            .interface = .wan,
            .src_ip = state.upstream_dns,
            .dst_ip = harness.WAN_IP,
            .src_port = 53,
            .dst_port = r.relay_id, // the relay_id was used as the src port on the relayed query
        };

        const dns_payload_len: u16 = 20; // minimal DNS response
        const udp_len: u16 = 8 + dns_payload_len;
        const ip_total: u16 = 20 + udp_len;

        @memset(&pkt.buf, 0);
        writeEthernet(&pkt.buf, harness.WAN_MAC, harness.WAN_GATEWAY_MAC, h.EthernetHeader.IPv4);
        writeIpv4(&pkt.buf, state.upstream_dns, harness.WAN_IP, 17, 64, ip_total);
        writeUdp(&pkt.buf, 34, 53, r.relay_id, udp_len);

        // DNS header: transaction ID = relay_id (the router will translate back to query_id)
        pkt.buf[42] = @truncate(r.relay_id >> 8);
        pkt.buf[43] = @truncate(r.relay_id);
        pkt.buf[44] = 0x81; // flags: response, recursion desired, recursion available
        pkt.buf[45] = 0x80;

        pkt.len = @intCast(14 + @as(u32, ip_total));
        return pkt;
    }

    // No active DNS relays — send a DNS query to create one
    return generateUdpDnsQuery(random);
}

fn generateTcpToPort80(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{
        .kind = .tcp_to_port_80,
        .protocol = 6,
        .interface = .lan,
        .tcp_flags = 0x02, // SYN
    };
    const host = randomLanHost(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = harness.LAN_IP; // router's LAN IP
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = 80;
    pkt.src_mac = host.mac;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, harness.LAN_IP, 6, 64, 40);
    writeTcp(&pkt.buf, 34, pkt.src_port, 80, 0x02); // SYN

    pkt.len = 54;
    return pkt;
}

fn generateUdpToUnhandledPort(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{
        .kind = .udp_to_unhandled_port,
        .protocol = 17,
        .interface = .lan,
    };
    const host = randomLanHost(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = harness.LAN_IP;
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    // Pick a port that's NOT handled (not 53, 67, 68, 1900, 5351)
    pkt.dst_port = random.intRangeAtMost(u16, 9000, 65535);
    pkt.src_mac = host.mac;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, harness.LAN_IP, 17, 64, 28);
    writeUdp(&pkt.buf, 34, pkt.src_port, pkt.dst_port, 8);

    pkt.len = 42;
    return pkt;
}

fn generatePcpMapRequest(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{
        .kind = .pcp_map_request,
        .protocol = 17,
        .interface = .lan,
    };
    const host = randomLanHost(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = harness.LAN_IP;
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = 5351;
    pkt.src_mac = host.mac;

    // PCP MAP request: 24-byte header + 36-byte MAP opcode = 60 bytes payload
    const pcp_payload_len: u16 = 60;
    const udp_len: u16 = 8 + pcp_payload_len;
    const ip_total: u16 = 20 + udp_len;

    @memset(&pkt.buf, 0);
    writeEthernet(&pkt.buf, harness.LAN_MAC, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, harness.LAN_IP, 17, 64, ip_total);
    writeUdp(&pkt.buf, 34, pkt.src_port, 5351, udp_len);

    // PCP header (starts at byte 42)
    pkt.buf[42] = 2; // version
    pkt.buf[43] = 1; // opcode MAP (request, R=0)
    // lifetime (4 bytes BE at offset 46)
    const lifetime = random.intRangeAtMost(u32, 120, 7200);
    pkt.buf[46] = @intCast((lifetime >> 24) & 0xFF);
    pkt.buf[47] = @intCast((lifetime >> 16) & 0xFF);
    pkt.buf[48] = @intCast((lifetime >> 8) & 0xFF);
    pkt.buf[49] = @intCast(lifetime & 0xFF);
    // client IP: v4-mapped at offset 50
    pkt.buf[60] = 0xff;
    pkt.buf[61] = 0xff;
    @memcpy(pkt.buf[62..66], &host.ip);

    // MAP opcode data (starts at byte 66)
    // nonce (12 bytes)
    for (0..12) |i| {
        pkt.buf[66 + i] = random.int(u8);
    }
    // protocol
    pkt.buf[78] = if (random.boolean()) 6 else 17;
    // internal port (2 bytes BE at offset 82)
    const int_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.buf[82] = @intCast(int_port >> 8);
    pkt.buf[83] = @intCast(int_port & 0xFF);
    // suggested external port (2 bytes BE at offset 84)
    const ext_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.buf[84] = @intCast(ext_port >> 8);
    pkt.buf[85] = @intCast(ext_port & 0xFF);

    pkt.len = 14 + @as(u32, ip_total);
    return pkt;
}

fn generateSsdpMsearch(random: std.Random) GeneratedPacket {
    var pkt = GeneratedPacket{
        .kind = .upnp_ssdp_msearch,
        .protocol = 17,
        .interface = .lan,
    };
    const host = randomLanHost(random);
    pkt.src_ip = host.ip;
    pkt.dst_ip = .{ 239, 255, 255, 250 };
    pkt.src_port = random.intRangeAtMost(u16, 1024, 65535);
    pkt.dst_port = 1900;
    pkt.src_mac = host.mac;

    const payload = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\n\r\n";
    const udp_len: u16 = 8 + payload.len;
    const ip_total: u16 = 20 + udp_len;

    @memset(&pkt.buf, 0);
    const mcast_mac: [6]u8 = .{ 0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa };
    writeEthernet(&pkt.buf, mcast_mac, host.mac, h.EthernetHeader.IPv4);
    writeIpv4(&pkt.buf, host.ip, pkt.dst_ip, 17, 64, ip_total);
    writeUdp(&pkt.buf, 34, pkt.src_port, 1900, udp_len);

    @memcpy(pkt.buf[42..][0..payload.len], payload);

    pkt.len = 14 + @as(u32, ip_total);
    return pkt;
}
