const lib = @import("lib");

const arp = @import("arp.zig");
const main = @import("main.zig");
const util = @import("util.zig");

const syscall = lib.syscall;

const RouterContext = main.RouterContext;

pub const TABLE_SIZE = 128;

const TCP_SYN_TIMEOUT_NS: u64 = 30_000_000_000;
const TCP_EST_TIMEOUT_NS: u64 = 300_000_000_000;
const TCP_FIN_TIMEOUT_NS: u64 = 30_000_000_000;
const UDP_TIMEOUT_NS: u64 = 120_000_000_000;
const UDP_DNS_TIMEOUT_NS: u64 = 30_000_000_000;
const ICMP_TIMEOUT_NS: u64 = 60_000_000_000;

pub const TcpState = enum(u8) { none, syn_sent, established, fin_wait };

pub const NatEntry = struct {
    valid: bool,
    protocol: util.Protocol,
    lan_ip: [4]u8,
    lan_port: u16,
    wan_port: u16,
    timestamp_ns: u64,
    tcp_state: TcpState,
    dst_ip: [4]u8,
    dst_port: u16,
};

pub const empty = NatEntry{
    .valid = false, .protocol = .icmp,
    .lan_ip = .{ 0, 0, 0, 0 }, .lan_port = 0, .wan_port = 0, .timestamp_ns = 0,
    .tcp_state = .none, .dst_ip = .{ 0, 0, 0, 0 }, .dst_port = 0,
};

fn natTimeout(entry: *const NatEntry) u64 {
    return switch (entry.protocol) {
        .icmp => ICMP_TIMEOUT_NS,
        .udp => if (entry.dst_port == 53) UDP_DNS_TIMEOUT_NS else UDP_TIMEOUT_NS,
        .tcp => switch (entry.tcp_state) {
            .syn_sent => TCP_SYN_TIMEOUT_NS,
            .established => TCP_EST_TIMEOUT_NS,
            .fin_wait => TCP_FIN_TIMEOUT_NS,
            .none => UDP_TIMEOUT_NS,
        },
    };
}

pub fn expire(table: *[TABLE_SIZE]NatEntry) void {
    const ts = util.now();
    for (table) |*e| {
        if (e.valid and ts -| e.timestamp_ns > natTimeout(e)) {
            e.valid = false;
        }
    }
}

pub fn updateTcpState(entry: *NatEntry, pkt: []const u8, len: u32, transport_start: usize) void {
    if (entry.protocol != .tcp) return;
    if (transport_start + 14 > len) return;

    const flags = pkt[transport_start + 13];
    const syn = (flags & 0x02) != 0;
    const fin = (flags & 0x01) != 0;
    const rst = (flags & 0x04) != 0;
    const ack = (flags & 0x10) != 0;

    switch (entry.tcp_state) {
        .none, .syn_sent => {
            if (syn and !ack) {
                entry.tcp_state = .syn_sent;
            } else if (ack) {
                entry.tcp_state = .established;
            }
        },
        .established => {
            if (fin or rst) {
                entry.tcp_state = .fin_wait;
            }
        },
        .fin_wait => {
            if (rst) {
                entry.valid = false;
            }
        },
    }
    entry.timestamp_ns = util.now();
}

fn logNat(action: []const u8, entry: *const NatEntry) void {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos = util.appendStr(&buf, pos, "nat: ");
    pos = util.appendStr(&buf, pos, action);
    pos = util.appendStr(&buf, pos, " ");
    pos = util.appendStr(&buf, pos, switch (entry.protocol) {
        .icmp => "icmp",
        .tcp => "tcp",
        .udp => "udp",
    });
    pos = util.appendStr(&buf, pos, " ");
    pos = util.appendIp(&buf, pos, entry.lan_ip);
    pos = util.appendStr(&buf, pos, ":");
    pos = util.appendDec(&buf, pos, entry.lan_port);
    pos = util.appendStr(&buf, pos, " -> ");
    pos = util.appendIp(&buf, pos, entry.dst_ip);
    pos = util.appendStr(&buf, pos, ":");
    pos = util.appendDec(&buf, pos, entry.dst_port);
    pos = util.appendStr(&buf, pos, " (wan:");
    pos = util.appendDec(&buf, pos, entry.wan_port);
    pos = util.appendStr(&buf, pos, ")\n");
    syscall.write(buf[0..pos]);
}

pub fn lookupOutbound(table: *[TABLE_SIZE]NatEntry, proto: util.Protocol, lip: [4]u8, lport: u16) ?*NatEntry {
    for (table) |*e| {
        if (e.valid and e.protocol == proto and util.eql(&e.lan_ip, &lip) and e.lan_port == lport) {
            e.timestamp_ns = util.now();
            return e;
        }
    }
    return null;
}

pub fn createOutbound(ctx: *RouterContext, proto: util.Protocol, lip: [4]u8, lport: u16, dip: [4]u8, dport: u16) ?*NatEntry {
    const ts = util.now();
    const tcp_state: TcpState = if (proto == .tcp) .syn_sent else .none;
    var oldest_idx: usize = 0;
    var oldest_ts: u64 = ts;
    for (&ctx.nat_table, 0..) |*e, i| {
        if (!e.valid) {
            e.* = .{ .valid = true, .protocol = proto, .lan_ip = lip,
                .lan_port = lport, .wan_port = ctx.next_nat_port, .timestamp_ns = ts,
                .tcp_state = tcp_state, .dst_ip = dip, .dst_port = dport };
            ctx.next_nat_port +%= 1;
            if (ctx.next_nat_port < 10000) ctx.next_nat_port = 10000;
            logNat("new", e);
            return e;
        }
        if (e.timestamp_ns < oldest_ts) {
            oldest_ts = e.timestamp_ns;
            oldest_idx = i;
        }
    }
    ctx.nat_table[oldest_idx] = .{ .valid = true, .protocol = proto, .lan_ip = lip,
        .lan_port = lport, .wan_port = ctx.next_nat_port, .timestamp_ns = ts,
        .tcp_state = tcp_state, .dst_ip = dip, .dst_port = dport };
    ctx.next_nat_port +%= 1;
    if (ctx.next_nat_port < 10000) ctx.next_nat_port = 10000;
    logNat("new", &ctx.nat_table[oldest_idx]);
    return &ctx.nat_table[oldest_idx];
}

pub fn lookupInbound(table: *[TABLE_SIZE]NatEntry, proto: util.Protocol, wport: u16) ?*NatEntry {
    for (table) |*e| {
        if (e.valid and e.protocol == proto and e.wan_port == wport) {
            e.timestamp_ns = util.now();
            return e;
        }
    }
    return null;
}

pub fn forwardLanToWan(ctx: *RouterContext, pkt: []u8, len: u32) void {
    if (len < 34) return;

    var dst_ip: [4]u8 = undefined;
    @memcpy(&dst_ip, pkt[30..34]);

    if (util.eql(&dst_ip, &ctx.lan_ip)) return;
    if (main.isInLanSubnet(dst_ip)) return;

    const gateway_mac = arp.lookup(&ctx.wan_arp, .{ 10, 0, 2, 1 }) orelse {
        arp.sendRequest(ctx, .wan, .{ 10, 0, 2, 1 });
        return;
    };

    const protocol = pkt[23];
    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;

    if (protocol == 1) {
        const icmp_start = 14 + ip_hdr_len;
        if (icmp_start + 8 > len) return;
        if (pkt[icmp_start] != 8) return;

        const orig_id = util.readU16Be(pkt[icmp_start + 4 ..][0..2]);
        var src_ip: [4]u8 = undefined;
        @memcpy(&src_ip, pkt[26..30]);

        var dst_ip_nat: [4]u8 = undefined;
        @memcpy(&dst_ip_nat, pkt[30..34]);
        const nat_entry = lookupOutbound(&ctx.nat_table, .icmp, src_ip, orig_id) orelse
            (createOutbound(ctx, .icmp, src_ip, orig_id, dst_ip_nat, 0) orelse return);

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &ctx.wan_mac);
        @memcpy(pkt[26..30], &ctx.wan_ip);
        util.writeU16Be(pkt[icmp_start + 4 ..][0..2], nat_entry.wan_port);

        pkt[icmp_start + 2] = 0;
        pkt[icmp_start + 3] = 0;
        const icmp_cs = util.computeChecksum(pkt[icmp_start..len]);
        pkt[icmp_start + 2] = @truncate(icmp_cs >> 8);
        pkt[icmp_start + 3] = @truncate(icmp_cs);

        pkt[24] = 0;
        pkt[25] = 0;
        const ip_cs = util.computeChecksum(pkt[14..][0..ip_hdr_len]);
        pkt[24] = @truncate(ip_cs >> 8);
        pkt[25] = @truncate(ip_cs);

        _ = ctx.wan_chan.send(pkt[0..len]);
    } else if (protocol == 6 or protocol == 17) {
        const transport_start = 14 + ip_hdr_len;
        if (transport_start + 4 > len) return;

        const orig_port = util.readU16Be(pkt[transport_start..][0..2]);
        var src_ip: [4]u8 = undefined;
        @memcpy(&src_ip, pkt[26..30]);

        var dst_ip_tcp: [4]u8 = undefined;
        @memcpy(&dst_ip_tcp, pkt[30..34]);
        const dst_port_tcp = util.readU16Be(pkt[transport_start + 2 ..][0..2]);
        const proto: util.Protocol = if (protocol == 6) .tcp else .udp;
        const nat_entry = lookupOutbound(&ctx.nat_table, proto, src_ip, orig_port) orelse
            (createOutbound(ctx, proto, src_ip, orig_port, dst_ip_tcp, dst_port_tcp) orelse return);

        if (protocol == 6) {
            updateTcpState(nat_entry, pkt, len, transport_start);
        }

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &ctx.wan_mac);

        if (protocol == 6) {
            util.tcpChecksumAdjust(pkt, transport_start, len, src_ip, ctx.wan_ip, orig_port, nat_entry.wan_port);
        } else if (transport_start + 8 <= len) {
            pkt[transport_start + 6] = 0;
            pkt[transport_start + 7] = 0;
        }

        @memcpy(pkt[26..30], &ctx.wan_ip);
        util.writeU16Be(pkt[transport_start..][0..2], nat_entry.wan_port);

        pkt[24] = 0;
        pkt[25] = 0;
        const ip_cs = util.computeChecksum(pkt[14..][0..ip_hdr_len]);
        pkt[24] = @truncate(ip_cs >> 8);
        pkt[25] = @truncate(ip_cs);

        ctx.wan_stats.tx_packets += 1;
        ctx.wan_stats.tx_bytes += len;
        _ = ctx.wan_chan.send(pkt[0..len]);
    }
}

pub fn forwardWanToLan(ctx: *RouterContext, pkt: []u8, len: u32) void {
    if (len < 34) return;

    var dst_ip: [4]u8 = undefined;
    @memcpy(&dst_ip, pkt[30..34]);
    if (!util.eql(&dst_ip, &ctx.wan_ip)) return;

    const protocol = pkt[23];
    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;

    if (protocol == 1) {
        const icmp_start = 14 + ip_hdr_len;
        if (icmp_start + 8 > len) return;
        if (pkt[icmp_start] != 0) return;

        const reply_id = util.readU16Be(pkt[icmp_start + 4 ..][0..2]);
        const nat_entry = lookupInbound(&ctx.nat_table, .icmp, reply_id) orelse return;

        const dst_mac = arp.lookup(&ctx.lan_arp, nat_entry.lan_ip) orelse return;

        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &ctx.lan_mac);
        @memcpy(pkt[30..34], &nat_entry.lan_ip);
        util.writeU16Be(pkt[icmp_start + 4 ..][0..2], nat_entry.lan_port);

        pkt[icmp_start + 2] = 0;
        pkt[icmp_start + 3] = 0;
        const icmp_cs = util.computeChecksum(pkt[icmp_start..len]);
        pkt[icmp_start + 2] = @truncate(icmp_cs >> 8);
        pkt[icmp_start + 3] = @truncate(icmp_cs);

        pkt[24] = 0;
        pkt[25] = 0;
        const ip_cs = util.computeChecksum(pkt[14..][0..ip_hdr_len]);
        pkt[24] = @truncate(ip_cs >> 8);
        pkt[25] = @truncate(ip_cs);

        if (ctx.lan_chan) |*ch| {
            _ = ch.send(pkt[0..len]);
        }
    } else if (protocol == 6 or protocol == 17) {
        const transport_start = 14 + ip_hdr_len;
        if (transport_start + 4 > len) return;

        const dst_port = util.readU16Be(pkt[transport_start + 2 ..][0..2]);
        const proto: util.Protocol = if (protocol == 6) .tcp else .udp;
        const nat_entry = lookupInbound(&ctx.nat_table, proto, dst_port) orelse return;

        if (protocol == 6) {
            updateTcpState(nat_entry, pkt, len, transport_start);
        }

        const dst_mac = arp.lookup(&ctx.lan_arp, nat_entry.lan_ip) orelse return;

        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &ctx.lan_mac);

        var old_dst_ip: [4]u8 = undefined;
        @memcpy(&old_dst_ip, pkt[30..34]);

        if (protocol == 6) {
            util.tcpChecksumAdjust(pkt, transport_start, len, old_dst_ip, nat_entry.lan_ip, dst_port, nat_entry.lan_port);
        } else if (transport_start + 8 <= len) {
            pkt[transport_start + 6] = 0;
            pkt[transport_start + 7] = 0;
        }

        @memcpy(pkt[30..34], &nat_entry.lan_ip);
        util.writeU16Be(pkt[transport_start + 2 ..][0..2], nat_entry.lan_port);

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
    }
}
