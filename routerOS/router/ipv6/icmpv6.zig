const router = @import("router");

const main = router.state;
const util = router.util;

const Interface = main.Interface;

var reply_buf: [1500]u8 = undefined;

/// Handle ICMPv6 Echo Request (type 128) → send Echo Reply (type 129).
pub fn handleEchoRequest(iface: Interface, pkt: []u8, len: u32) ?[]const u8 {
    if (len < 58) return null; // 14 eth + 40 ipv6 + 4 icmpv6 minimum
    if (pkt[54] != 128) return null;

    const ifc = main.getIface(iface);
    const reply_len: usize = @intCast(len);
    if (reply_len > reply_buf.len) return null;

    @memcpy(reply_buf[0..reply_len], pkt[0..reply_len]);

    // Swap Ethernet src/dst
    @memcpy(reply_buf[0..6], pkt[6..12]);
    @memcpy(reply_buf[6..12], &ifc.mac);

    // Swap IPv6 src/dst
    @memcpy(reply_buf[22..38], pkt[38..54]); // src = old dst (our address)
    @memcpy(reply_buf[38..54], pkt[22..38]); // dst = old src

    // Change type from 128 (request) to 129 (reply)
    reply_buf[54] = 129;

    // Recompute ICMPv6 checksum
    reply_buf[56] = 0;
    reply_buf[57] = 0;
    var src_ip6: [16]u8 = undefined;
    var dst_ip6: [16]u8 = undefined;
    @memcpy(&src_ip6, reply_buf[22..38]);
    @memcpy(&dst_ip6, reply_buf[38..54]);
    const cs = util.computeIcmpv6Checksum(src_ip6, dst_ip6, reply_buf[54..reply_len]);
    reply_buf[56] = @truncate(cs >> 8);
    reply_buf[57] = @truncate(cs);

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
    @memcpy(error_buf[0..6], orig_pkt[6..12]); // dst = original src
    @memcpy(error_buf[6..12], &ifc.mac);
    error_buf[12] = 0x86;
    error_buf[13] = 0xDD;

    // IPv6
    error_buf[14] = 0x60;
    util.writeU16Be(error_buf[18..20], payload_len);
    error_buf[20] = 58; // ICMPv6
    error_buf[21] = 255;

    // Source = our link-local (or global if available)
    if (ifc.ip6_global_valid) {
        @memcpy(error_buf[22..38], &ifc.ip6_global);
    } else {
        @memcpy(error_buf[22..38], &ifc.ip6_link_local);
    }
    // Destination = original source
    @memcpy(error_buf[38..54], orig_pkt[22..38]);

    // ICMPv6 error header
    error_buf[54] = icmp_type;
    error_buf[55] = icmp_code;
    // checksum at 56-57
    // unused/pointer at 58-61 (zero)

    // Original packet (starting from IPv6 header, skip Ethernet)
    @memcpy(error_buf[62..][0..orig_include], orig_pkt[14..][0..orig_include]);

    // ICMPv6 checksum
    var src_ip6: [16]u8 = undefined;
    var dst_ip6: [16]u8 = undefined;
    @memcpy(&src_ip6, error_buf[22..38]);
    @memcpy(&dst_ip6, error_buf[38..54]);
    const cs = util.computeIcmpv6Checksum(src_ip6, dst_ip6, error_buf[54..total_len]);
    error_buf[56] = @truncate(cs >> 8);
    error_buf[57] = @truncate(cs);

    _ = ifc.txSendLocal(error_buf[0..total_len]);
}
