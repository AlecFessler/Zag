const main = @import("main.zig");
const util = @import("util.zig");

const RouterContext = main.RouterContext;

pub const TABLE_SIZE = 32;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

pub const DhcpLease = struct {
    mac: [6]u8,
    ip: [4]u8,
    valid: bool,
};

pub const empty = DhcpLease{ .mac = .{ 0, 0, 0, 0, 0, 0 }, .ip = .{ 0, 0, 0, 0 }, .valid = false };

fn findLease(leases: []const DhcpLease, mac: [6]u8) ?[4]u8 {
    for (leases) |l| {
        if (l.valid and util.eql(&l.mac, &mac)) return l.ip;
    }
    return null;
}

fn allocateLease(ctx: *RouterContext, mac: [6]u8) ?[4]u8 {
    if (findLease(&ctx.dhcp_leases, mac)) |ip| return ip;
    for (&ctx.dhcp_leases) |*l| {
        if (!l.valid) {
            l.ip = .{ 192, 168, 1, ctx.dhcp_next_ip };
            @memcpy(&l.mac, &mac);
            l.valid = true;
            ctx.dhcp_next_ip +%= 1;
            if (ctx.dhcp_next_ip < 100) ctx.dhcp_next_ip = 100;
            return l.ip;
        }
    }
    return null;
}

pub fn handle(ctx: *RouterContext, pkt: []const u8, len: u32) void {
    if (!ctx.has_lan) return;
    if (len < 282) return;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;

    const src_port = util.readU16Be(pkt[udp_start..][0..2]);
    const dst_port = util.readU16Be(pkt[udp_start + 2 ..][0..2]);
    if (src_port != 68 or dst_port != 67) return;

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
        opt_idx += 2 + opt_len;
    }

    if (msg_type == DHCP_DISCOVER or msg_type == DHCP_REQUEST) {
        const offer_ip = allocateLease(ctx, client_mac) orelse return;
        const response_type: u8 = if (msg_type == DHCP_DISCOVER) DHCP_OFFER else DHCP_ACK;
        sendResponse(ctx, pkt[dhcp_start..], client_mac, offer_ip, response_type);
    }
}

fn sendResponse(ctx: *RouterContext, request: []const u8, client_mac: [6]u8, offer_ip: [4]u8, msg_type: u8) void {
    var pkt: [600]u8 = undefined;
    @memset(&pkt, 0);

    @memset(pkt[0..6], 0xFF);
    @memcpy(pkt[6..12], &ctx.lan_mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    pkt[15] = 0x00;
    pkt[22] = 64;
    pkt[23] = 17;
    @memcpy(pkt[26..30], &ctx.lan_ip);
    @memset(pkt[30..34], 0xFF);

    const udp_start: usize = 34;
    util.writeU16Be(pkt[udp_start..][0..2], 67);
    util.writeU16Be(pkt[udp_start + 2 ..][0..2], 68);

    const dhcp_start: usize = udp_start + 8;
    pkt[dhcp_start] = 2;
    pkt[dhcp_start + 1] = 1;
    pkt[dhcp_start + 2] = 6;
    pkt[dhcp_start + 3] = 0;
    @memcpy(pkt[dhcp_start + 4 ..][0..4], request[4..8]);
    @memcpy(pkt[dhcp_start + 16 ..][0..4], &offer_ip);
    @memcpy(pkt[dhcp_start + 20 ..][0..4], &ctx.lan_ip);
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
    @memcpy(pkt[opt + 2 ..][0..4], &ctx.lan_ip);
    opt += 6;

    pkt[opt] = 6;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &ctx.lan_ip);
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
    @memcpy(pkt[opt + 2 ..][0..4], &ctx.lan_ip);
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

    const total_len = 14 + ip_total;
    const send_len = if (total_len < 60) @as(usize, 60) else @as(usize, @intCast(total_len));
    if (ctx.lan_chan) |*ch| {
        _ = ch.send(pkt[0..send_len]);
    }
}
