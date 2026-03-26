const router = @import("router");

const arp = router.net.arp;
const h = router.net.headers;
const main = router.state;
const util = router.util;

pub const PingState = enum { idle, arp_pending, echo_sent };
pub const TracerouteState = enum { idle, arp_pending, probe_sent };

const ping_id: u16 = 0x5A47;
const timeout_ns: u64 = 3_000_000_000;
const total: u8 = 4;

pub fn sendEchoRequest() void {
    var pkt: [98]u8 = undefined;
    @memset(&pkt, 0);

    const ifc = main.getIface(main.ping_iface);

    const eth = h.EthernetHeader.parseMut(&pkt) orelse unreachable;
    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse unreachable;
    const icmp = h.IcmpHeader.parseMut(pkt[34..]) orelse unreachable;

    @memcpy(&eth.dst_mac, &main.ping_target_mac);
    @memcpy(&eth.src_mac, &ifc.mac);
    eth.setEtherType(h.EthernetHeader.IPv4);

    ip.ver_ihl = 0x45;
    ip.setTotalLen(84);
    ip.setIdentification(ping_id);
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_ICMP;
    @memcpy(&ip.src_ip, &ifc.ip);
    @memcpy(&ip.dst_ip, &main.ping_target_ip);
    ip.computeAndSetChecksum(&pkt);

    icmp.icmp_type = h.IcmpHeader.TYPE_ECHO_REQUEST;
    icmp.setId(ping_id);
    icmp.setSeq(main.ping_seq);
    icmp.computeAndSetChecksum(pkt[34..98]);

    main.ping_start_ns = util.now();
    main.ping_state = .echo_sent;
    _ = ifc.txSendLocal(&pkt);
}

pub fn handleEchoReply(pkt: []const u8, len: u32) void {
    if (main.ping_state != .echo_sent) return;
    if (len < 42) return;

    const ip = h.Ipv4Header.parse(pkt[14..]) orelse return;
    if (ip.protocol != h.Ipv4Header.PROTO_ICMP) return;

    const icmp_start = 14 + ip.headerLen();
    if (icmp_start + 8 > len) return;

    const icmp = h.IcmpHeader.parse(pkt[icmp_start..]) orelse return;
    if (icmp.icmp_type != h.IcmpHeader.TYPE_ECHO_REPLY) return;

    if (icmp.id() != ping_id or icmp.sequence() != main.ping_seq) return;

    const rtt_us = (util.now() -| main.ping_start_ns) / 1000;
    main.ping_received += 1;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = util.appendStr(&resp, pos, "reply from ");
    pos = util.appendIp(&resp, pos, main.ping_target_ip);
    pos = util.appendStr(&resp, pos, ": seq=");
    pos = util.appendDec(&resp, pos, main.ping_seq);
    pos = util.appendStr(&resp, pos, " time=");
    pos = util.appendDec(&resp, pos, rtt_us);
    pos = util.appendStr(&resp, pos, "us");
    if (main.console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    main.ping_count += 1;
    if (main.ping_count >= total) {
        sendSummary();
        main.ping_state = .idle;
    } else {
        main.ping_seq += 1;
        sendEchoRequest();
    }
}

fn sendSummary() void {
    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = util.appendStr(&resp, pos, "--- ping ");
    pos = util.appendIp(&resp, pos, main.ping_target_ip);
    pos = util.appendStr(&resp, pos, ": ");
    pos = util.appendDec(&resp, pos, total);
    pos = util.appendStr(&resp, pos, " sent, ");
    pos = util.appendDec(&resp, pos, main.ping_received);
    pos = util.appendStr(&resp, pos, " received ---");
    if (main.console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }
}

pub fn checkTracerouteTimeout() void {
    if (main.traceroute_state == .idle) return;
    if (util.now() -| main.traceroute_start_ns < timeout_ns) return;

    if (main.traceroute_state == .arp_pending) {
        var resp: [128]u8 = undefined;
        var pos: usize = 0;
        pos = util.appendStr(&resp, pos, "traceroute: ARP timeout");
        if (main.console_chan) |*chan| {
            _ = chan.send(resp[0..pos]);
            _ = chan.send("---");
        }
        main.traceroute_state = .idle;
        return;
    }

    // Probe timed out — report * for this hop
    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = util.appendDec(&resp, pos, main.traceroute_ttl);
    pos = util.appendStr(&resp, pos, "  *");
    if (main.console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    main.traceroute_ttl += 1;
    if (main.traceroute_ttl > main.traceroute_max_hops) {
        if (main.console_chan) |*chan| {
            _ = chan.send("---");
        }
        main.traceroute_state = .idle;
    } else {
        sendTracerouteProbe();
    }
}

pub fn sendTracerouteProbe() void {
    var pkt: [98]u8 = undefined;
    @memset(&pkt, 0);

    const ifc = main.getIface(main.traceroute_iface);

    const eth = h.EthernetHeader.parseMut(&pkt) orelse unreachable;
    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse unreachable;
    const icmp = h.IcmpHeader.parseMut(pkt[34..]) orelse unreachable;

    @memcpy(&eth.dst_mac, &main.traceroute_target_mac);
    @memcpy(&eth.src_mac, &ifc.mac);
    eth.setEtherType(h.EthernetHeader.IPv4);

    ip.ver_ihl = 0x45;
    ip.setTotalLen(84);
    ip.setIdentification(traceroute_id);
    ip.ttl = main.traceroute_ttl;
    ip.protocol = h.Ipv4Header.PROTO_ICMP;
    @memcpy(&ip.src_ip, &ifc.ip);
    @memcpy(&ip.dst_ip, &main.traceroute_target_ip);
    ip.computeAndSetChecksum(&pkt);

    icmp.icmp_type = h.IcmpHeader.TYPE_ECHO_REQUEST;
    icmp.setId(traceroute_id);
    icmp.setSeq(@as(u16, main.traceroute_ttl));
    icmp.computeAndSetChecksum(pkt[34..98]);

    main.traceroute_start_ns = util.now();
    main.traceroute_state = .probe_sent;
    _ = ifc.txSendLocal(&pkt);
}

const traceroute_id: u16 = 0x5A48;

/// Handle ICMP Time Exceeded (type 11) — used by traceroute.
/// The payload contains the original IP header + 8 bytes of ICMP.
pub fn handleTimeExceeded(pkt: []const u8, len: u32) void {
    if (main.traceroute_state != .probe_sent) return;
    if (len < 42) return;

    const ip = h.Ipv4Header.parse(pkt[14..]) orelse return;
    if (ip.protocol != h.Ipv4Header.PROTO_ICMP) return;

    const icmp_start: usize = 14 + ip.headerLen();
    if (icmp_start + 8 > len) return;

    const icmp = h.IcmpHeader.parse(pkt[icmp_start..]) orelse return;
    if (icmp.icmp_type != h.IcmpHeader.TYPE_TIME_EXCEEDED) return;

    // The ICMP payload starts at icmp_start + 8 (after type/code/checksum/unused)
    // It contains the original IP header + first 8 bytes of original ICMP
    const orig_ip_start = icmp_start + 8;
    if (orig_ip_start + 28 > len) return; // need at least orig IP (20) + ICMP (8)

    const orig_ip = h.Ipv4Header.parse(pkt[orig_ip_start..]) orelse return;
    const orig_icmp_start = orig_ip_start + orig_ip.headerLen();
    if (orig_icmp_start + 4 > len) return;

    // Check that original packet was our traceroute probe
    const orig_icmp = h.IcmpHeader.parse(pkt[orig_icmp_start..]) orelse return;
    if (orig_icmp.id() != traceroute_id) return;

    // Report the hop
    const src_ip = ip.src_ip;
    const rtt_us = (util.now() -| main.traceroute_start_ns) / 1000;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = util.appendDec(&resp, pos, main.traceroute_ttl);
    pos = util.appendStr(&resp, pos, "  ");
    pos = util.appendIp(&resp, pos, src_ip);
    pos = util.appendStr(&resp, pos, "  ");
    pos = util.appendDec(&resp, pos, rtt_us);
    pos = util.appendStr(&resp, pos, "us");
    if (main.console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    // Next hop
    main.traceroute_ttl += 1;
    if (main.traceroute_ttl > main.traceroute_max_hops) {
        if (main.console_chan) |*chan| {
            _ = chan.send("---");
        }
        main.traceroute_state = .idle;
    } else {
        sendTracerouteProbe();
    }
}

/// Handle echo reply during traceroute — means we reached the destination.
pub fn handleTracerouteEchoReply(pkt: []const u8, len: u32) void {
    if (main.traceroute_state != .probe_sent) return;
    if (len < 42) return;

    const ip = h.Ipv4Header.parse(pkt[14..]) orelse return;
    if (ip.protocol != h.Ipv4Header.PROTO_ICMP) return;

    const icmp_start: usize = 14 + ip.headerLen();
    if (icmp_start + 8 > len) return;

    const icmp = h.IcmpHeader.parse(pkt[icmp_start..]) orelse return;
    if (icmp.icmp_type != h.IcmpHeader.TYPE_ECHO_REPLY) return;

    if (icmp.id() != traceroute_id) return;

    const src_ip = ip.src_ip;
    const rtt_us = (util.now() -| main.traceroute_start_ns) / 1000;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = util.appendDec(&resp, pos, main.traceroute_ttl);
    pos = util.appendStr(&resp, pos, "  ");
    pos = util.appendIp(&resp, pos, src_ip);
    pos = util.appendStr(&resp, pos, "  ");
    pos = util.appendDec(&resp, pos, rtt_us);
    pos = util.appendStr(&resp, pos, "us");
    if (main.console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
        _ = chan.send("---");
    }

    main.traceroute_state = .idle;
}

pub fn checkTimeout() void {
    if (main.ping_state == .idle) return;
    if (util.now() -| main.ping_start_ns < timeout_ns) return;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    if (main.ping_state == .arp_pending) {
        pos = util.appendStr(&resp, pos, "ping: ARP timeout for ");
        pos = util.appendIp(&resp, pos, main.ping_target_ip);
    } else {
        pos = util.appendStr(&resp, pos, "request timeout: seq=");
        pos = util.appendDec(&resp, pos, main.ping_seq);
    }
    if (main.console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    main.ping_count += 1;
    if (main.ping_count >= total) {
        sendSummary();
        main.ping_state = .idle;
    } else {
        main.ping_seq += 1;
        if (main.ping_state == .arp_pending) {
            arp.sendRequest(main.ping_iface, main.ping_target_ip);
            main.ping_start_ns = util.now();
        } else {
            sendEchoRequest();
        }
    }
}
