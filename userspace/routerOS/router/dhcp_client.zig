const main = @import("main.zig");
const util = @import("util.zig");

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

pub const DhcpClientState = enum { idle, discovering, requesting, bound };

pub fn sendDiscover() void {
    var pkt: [600]u8 = undefined;
    @memset(&pkt, 0);

    @memset(pkt[0..6], 0xFF);
    @memcpy(pkt[6..12], &main.wan_iface.mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    pkt[22] = 64;
    pkt[23] = 17;
    @memset(pkt[26..30], 0);
    @memset(pkt[30..34], 0xFF);

    const udp_start: usize = 34;
    util.writeU16Be(pkt[udp_start..][0..2], 68);
    util.writeU16Be(pkt[udp_start + 2 ..][0..2], 67);

    const dhcp_start: usize = udp_start + 8;
    pkt[dhcp_start] = 1;
    pkt[dhcp_start + 1] = 1;
    pkt[dhcp_start + 2] = 6;
    pkt[dhcp_start + 3] = 0;

    pkt[dhcp_start + 4] = @truncate(main.dhcp_client_xid >> 24);
    pkt[dhcp_start + 5] = @truncate(main.dhcp_client_xid >> 16);
    pkt[dhcp_start + 6] = @truncate(main.dhcp_client_xid >> 8);
    pkt[dhcp_start + 7] = @truncate(main.dhcp_client_xid);

    @memcpy(pkt[dhcp_start + 28 ..][0..6], &main.wan_iface.mac);

    const magic: usize = dhcp_start + 236;
    pkt[magic] = 0x63;
    pkt[magic + 1] = 0x82;
    pkt[magic + 2] = 0x53;
    pkt[magic + 3] = 0x63;

    var opt: usize = magic + 4;
    pkt[opt] = 53;
    pkt[opt + 1] = 1;
    pkt[opt + 2] = DHCP_DISCOVER;
    opt += 3;
    pkt[opt] = 255;
    opt += 1;

    const total_dhcp = opt - dhcp_start;
    const udp_len: u16 = @truncate(8 + total_dhcp);
    util.writeU16Be(pkt[udp_start + 4 ..][0..2], udp_len);
    const ip_total: u16 = @truncate(20 + udp_len);
    util.writeU16Be(pkt[16..18], ip_total);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = util.computeChecksum(pkt[14..34]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    const send_len = @max(@as(usize, @intCast(14 + ip_total)), 60);
    _ = main.wan_iface.txSendLocal(pkt[0..send_len]);
    main.dhcp_client_state = .discovering;
    main.dhcp_client_start_ns = util.now();
    util.logEvent("dhcp-client: sent DISCOVER on WAN\n");
}

pub fn sendRequest() void {
    var pkt: [600]u8 = undefined;
    @memset(&pkt, 0);

    @memset(pkt[0..6], 0xFF);
    @memcpy(pkt[6..12], &main.wan_iface.mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    pkt[22] = 64;
    pkt[23] = 17;
    @memset(pkt[26..30], 0);
    @memset(pkt[30..34], 0xFF);

    const udp_start: usize = 34;
    util.writeU16Be(pkt[udp_start..][0..2], 68);
    util.writeU16Be(pkt[udp_start + 2 ..][0..2], 67);

    const dhcp_start: usize = udp_start + 8;
    pkt[dhcp_start] = 1;
    pkt[dhcp_start + 1] = 1;
    pkt[dhcp_start + 2] = 6;
    pkt[dhcp_start + 3] = 0;
    pkt[dhcp_start + 4] = @truncate(main.dhcp_client_xid >> 24);
    pkt[dhcp_start + 5] = @truncate(main.dhcp_client_xid >> 16);
    pkt[dhcp_start + 6] = @truncate(main.dhcp_client_xid >> 8);
    pkt[dhcp_start + 7] = @truncate(main.dhcp_client_xid);
    @memcpy(pkt[dhcp_start + 28 ..][0..6], &main.wan_iface.mac);

    const magic: usize = dhcp_start + 236;
    pkt[magic] = 0x63;
    pkt[magic + 1] = 0x82;
    pkt[magic + 2] = 0x53;
    pkt[magic + 3] = 0x63;

    var opt: usize = magic + 4;
    pkt[opt] = 53;
    pkt[opt + 1] = 1;
    pkt[opt + 2] = DHCP_REQUEST;
    opt += 3;

    pkt[opt] = 50;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &main.dhcp_offered_ip);
    opt += 6;

    pkt[opt] = 54;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &main.dhcp_server_ip);
    opt += 6;

    pkt[opt] = 255;
    opt += 1;

    const total_dhcp = opt - dhcp_start;
    const udp_len: u16 = @truncate(8 + total_dhcp);
    util.writeU16Be(pkt[udp_start + 4 ..][0..2], udp_len);
    const ip_total: u16 = @truncate(20 + udp_len);
    util.writeU16Be(pkt[16..18], ip_total);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = util.computeChecksum(pkt[14..34]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    const send_len = @max(@as(usize, @intCast(14 + ip_total)), 60);
    _ = main.wan_iface.txSendLocal(pkt[0..send_len]);
    main.dhcp_client_state = .requesting;
    main.dhcp_client_start_ns = util.now();
    util.logEvent("dhcp-client: sent REQUEST on WAN\n");
}

pub fn handleResponse(pkt: []const u8, len: u32) void {
    if (main.dhcp_client_state == .idle or main.dhcp_client_state == .bound) return;
    if (len < 282) return;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;
    if (pkt[23] != 17) return;

    const src_port = util.readU16Be(pkt[udp_start..][0..2]);
    const dst_port = util.readU16Be(pkt[udp_start + 2 ..][0..2]);
    if (src_port != 67 or dst_port != 68) return;

    const dhcp_start = udp_start + 8;
    if (dhcp_start + 240 > len) return;
    if (pkt[dhcp_start] != 2) return;

    const xid = @as(u32, pkt[dhcp_start + 4]) << 24 |
        @as(u32, pkt[dhcp_start + 5]) << 16 |
        @as(u32, pkt[dhcp_start + 6]) << 8 |
        pkt[dhcp_start + 7];
    if (xid != main.dhcp_client_xid) return;

    @memcpy(&main.dhcp_offered_ip, pkt[dhcp_start + 16 ..][0..4]);

    const magic_offset = dhcp_start + 236;
    if (pkt[magic_offset] != 0x63 or pkt[magic_offset + 1] != 0x82 or
        pkt[magic_offset + 2] != 0x53 or pkt[magic_offset + 3] != 0x63) return;

    var msg_type: u8 = 0;
    var opt_idx: u32 = magic_offset + 4;
    while (opt_idx + 1 < len) {
        const o = pkt[opt_idx];
        if (o == 255) break;
        if (o == 0) {
            opt_idx += 1;
            continue;
        }
        const olen = pkt[opt_idx + 1];
        if (o == 53 and olen >= 1) msg_type = pkt[opt_idx + 2];
        if (o == 54 and olen >= 4) @memcpy(&main.dhcp_server_ip, pkt[opt_idx + 2 ..][0..4]);
        if (o == 6 and olen >= 4) @memcpy(&main.upstream_dns, pkt[opt_idx + 2 ..][0..4]);
        opt_idx += 2 + olen;
    }

    if (msg_type == DHCP_OFFER and main.dhcp_client_state == .discovering) {
        var buf: [64]u8 = undefined;
        var pos: usize = 0;
        pos = util.appendStr(&buf, pos, "dhcp-client: offered ");
        pos = util.appendIp(&buf, pos, main.dhcp_offered_ip);
        pos = util.appendStr(&buf, pos, "\n");
        util.logEvent(buf[0..pos]);
        sendRequest();
    } else if (msg_type == DHCP_ACK and main.dhcp_client_state == .requesting) {
        main.wan_iface.ip = main.dhcp_offered_ip;
        main.dhcp_client_state = .bound;
        var buf: [64]u8 = undefined;
        var pos: usize = 0;
        pos = util.appendStr(&buf, pos, "dhcp-client: bound to ");
        pos = util.appendIp(&buf, pos, main.wan_iface.ip);
        pos = util.appendStr(&buf, pos, "\n");
        util.logEvent(buf[0..pos]);
    }
}

pub fn tick() void {
    if (main.dhcp_client_state == .idle or main.dhcp_client_state == .bound) return;
    if (util.now() -| main.dhcp_client_start_ns > 10_000_000_000) {
        util.logEvent("dhcp-client: timeout, retrying\n");
        main.dhcp_client_xid +%= 1;
        sendDiscover();
    }
}
