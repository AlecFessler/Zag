const arp = @import("arp.zig");
const main = @import("main.zig");
const util = @import("util.zig");

const RouterContext = main.RouterContext;

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

pub fn handlePortForward(ctx: *RouterContext, pkt: []u8, len: u32) bool {
    if (!ctx.has_lan) return false;
    if (len < 34) return false;

    const protocol = pkt[23];
    if (protocol != 6 and protocol != 17) return false;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const transport_start = 14 + ip_hdr_len;
    if (transport_start + 4 > len) return false;

    const dst_port = util.readU16Be(pkt[transport_start + 2 ..][0..2]);
    const proto: util.Protocol = if (protocol == 6) .tcp else .udp;

    const fwd = portFwdLookup(&ctx.port_forwards, proto, dst_port) orelse return false;

    const dst_mac = arp.lookup(&ctx.lan_arp, fwd.lan_ip) orelse {
        arp.sendRequest(ctx, .lan, fwd.lan_ip);
        return true;
    };

    var old_dst_ip: [4]u8 = undefined;
    @memcpy(&old_dst_ip, pkt[30..34]);

    @memcpy(pkt[0..6], &dst_mac);
    @memcpy(pkt[6..12], &ctx.lan_mac);
    @memcpy(pkt[30..34], &fwd.lan_ip);
    util.writeU16Be(pkt[transport_start + 2 ..][0..2], fwd.lan_port);

    if (protocol == 6) {
        util.tcpChecksumAdjust(pkt, transport_start, len, old_dst_ip, fwd.lan_ip, dst_port, fwd.lan_port);
    } else {
        pkt[transport_start + 6] = 0;
        pkt[transport_start + 7] = 0;
    }

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = util.computeChecksum(pkt[14..][0..ip_hdr_len]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    ctx.lan_stats.tx_packets += 1;
    ctx.lan_stats.tx_bytes += len;
    if (ctx.lan_chan) |*ch| {
        _ = ch.send(pkt[0..len]);
    }
    return true;
}
