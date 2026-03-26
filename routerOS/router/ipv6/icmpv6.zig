const router = @import("router");

const h = router.net.headers;
const main = router.state;
const util = router.util;

const Interface = main.Interface;

var reply_buf: [1500]u8 = undefined;

/// Handle ICMPv6 Echo Request (type 128) → send Echo Reply (type 129).
pub fn handleEchoRequest(iface: Interface, pkt: []u8, len: u32) ?[]const u8 {
    if (len < 58) return null; // 14 eth + 40 ipv6 + 4 icmpv6 minimum
    const req_icmpv6 = h.Icmpv6Header.parse(pkt[54..]) orelse return null;
    if (req_icmpv6.icmp_type != h.Icmpv6Header.TYPE_ECHO_REQUEST) return null;

    const ifc = main.getIface(iface);
    const reply_len: usize = @intCast(len);
    if (reply_len > reply_buf.len) return null;

    @memcpy(reply_buf[0..reply_len], pkt[0..reply_len]);

    // Swap Ethernet src/dst
    const reply_eth = h.EthernetHeader.parseMut(&reply_buf) orelse return null;
    const pkt_eth = h.EthernetHeader.parse(pkt) orelse return null;
    @memcpy(&reply_eth.dst_mac, &pkt_eth.src_mac);
    @memcpy(&reply_eth.src_mac, &ifc.mac);

    // Swap IPv6 src/dst
    const pkt_ip6 = h.Ipv6Header.parse(pkt[14..]) orelse return null;
    const reply_ip6 = h.Ipv6Header.parseMut(reply_buf[14..]) orelse return null;
    @memcpy(&reply_ip6.src_ip, &pkt_ip6.dst_ip); // src = old dst (our address)
    @memcpy(&reply_ip6.dst_ip, &pkt_ip6.src_ip); // dst = old src

    // Change type from 128 (request) to 129 (reply)
    const reply_icmpv6 = h.Icmpv6Header.parseMut(reply_buf[54..]) orelse return null;
    reply_icmpv6.icmp_type = h.Icmpv6Header.TYPE_ECHO_REPLY;

    // Recompute ICMPv6 checksum
    reply_icmpv6.zeroChecksum();
    var src_ip6: [16]u8 = undefined;
    var dst_ip6: [16]u8 = undefined;
    @memcpy(&src_ip6, &reply_ip6.src_ip);
    @memcpy(&dst_ip6, &reply_ip6.dst_ip);
    const cs = util.computeIcmpv6Checksum(src_ip6, dst_ip6, reply_buf[54..reply_len]);
    reply_icmpv6.setChecksum(cs);

    return reply_buf[0..reply_len];
}

/// Handle ICMPv6 Echo Reply (type 129) for console ping6.
pub fn handleEchoReply(pkt: []const u8, len: u32) void {
    _ = pkt;
    _ = len;
    // TODO: implement ping6 from console
}

var error_buf: [1280]u8 = undefined;

/// Send an ICMPv6 error message (Time Exceeded, Destination Unreachable).
pub fn sendError(iface: Interface, orig_pkt: []const u8, orig_len: u32, icmp_type: u8, icmp_code: u8) void {
    if (orig_len < 54) return; // Need at least IPv6 header
    const ifc = main.getIface(iface);
    @memset(&error_buf, 0);

    // Include as much of the original packet as fits in 1280 MTU
    // ICMPv6 error: 14 eth + 40 ipv6 + 8 icmpv6 header + original data
    const max_orig: usize = 1280 - 14 - 40 - 8;
    const orig_include: usize = @min(@as(usize, @intCast(orig_len)) - 14, max_orig);
    const payload_len: u16 = @truncate(8 + orig_include);
    const total_len: usize = 14 + 40 + 8 + orig_include;

    // Ethernet
    const orig_eth = h.EthernetHeader.parse(orig_pkt) orelse return;
    const eth = h.EthernetHeader.parseMut(&error_buf) orelse return;
    @memcpy(&eth.dst_mac, &orig_eth.src_mac); // dst = original src
    @memcpy(&eth.src_mac, &ifc.mac);
    eth.setEtherType(h.EthernetHeader.IPv6);

    // IPv6
    const orig_ip6 = h.Ipv6Header.parse(orig_pkt[14..]) orelse return;
    const ip6 = h.Ipv6Header.parseMut(error_buf[14..]) orelse return;
    ip6.ver_tc_fl[0] = 0x60;
    ip6.setPayloadLen(payload_len);
    ip6.next_header = 58; // ICMPv6
    ip6.hop_limit = 255;

    // Source = our link-local (or global if available)
    if (ifc.ip6_global_valid) {
        @memcpy(&ip6.src_ip, &ifc.ip6_global);
    } else {
        @memcpy(&ip6.src_ip, &ifc.ip6_link_local);
    }
    // Destination = original source
    @memcpy(&ip6.dst_ip, &orig_ip6.src_ip);

    // ICMPv6 error header
    const icmpv6 = h.Icmpv6Header.parseMut(error_buf[54..]) orelse return;
    icmpv6.icmp_type = icmp_type;
    icmpv6.code = icmp_code;
    // checksum at 56-57
    // unused/pointer at 58-61 (zero)

    // Original packet (starting from IPv6 header, skip Ethernet)
    @memcpy(error_buf[62..][0..orig_include], orig_pkt[14..][0..orig_include]);

    // ICMPv6 checksum
    var src_ip6: [16]u8 = undefined;
    var dst_ip6: [16]u8 = undefined;
    @memcpy(&src_ip6, &ip6.src_ip);
    @memcpy(&dst_ip6, &ip6.dst_ip);
    const cs = util.computeIcmpv6Checksum(src_ip6, dst_ip6, error_buf[54..total_len]);
    icmpv6.setChecksum(cs);

    _ = ifc.txSendLocal(error_buf[0..total_len]);
}
