const lib = @import("lib");

const arp = @import("arp.zig");
const dhcp_client = @import("dhcp_client.zig");
const dhcp_server = @import("dhcp_server.zig");
const dns = @import("dns.zig");
const firewall = @import("firewall.zig");
const frag = @import("frag.zig");
const nat = @import("nat.zig");
const ping_mod = @import("ping.zig");
const util = @import("util.zig");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

// ── Constants ───────────────────────────────────────────────────────────

const MAX_PERMS = 128;

pub const lan_subnet: [4]u8 = .{ 192, 168, 1, 0 };
pub const lan_mask: [4]u8 = .{ 255, 255, 255, 0 };
pub const lan_broadcast: [4]u8 = .{ 192, 168, 1, 255 };

const MAINTENANCE_INTERVAL_NS: u64 = 10_000_000_000;

// ── Types ───────────────────────────────────────────────────────────────

pub const Interface = enum { wan, lan };

pub const IfaceStats = struct {
    rx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_packets: u64 = 0,
    tx_bytes: u64 = 0,
    rx_dropped: u64 = 0,
};

// ── RouterContext ────────────────────────────────────────────────────────

pub const RouterContext = struct {
    // Interface channels
    wan_chan: channel_mod.Channel = undefined,
    lan_chan: ?channel_mod.Channel = null,
    console_chan: ?channel_mod.Channel = null,

    // Interface addresses
    wan_mac: [6]u8 = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 },
    lan_mac: [6]u8 = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 },
    wan_ip: [4]u8 = .{ 10, 0, 2, 15 },
    lan_ip: [4]u8 = .{ 192, 168, 1, 1 },

    // Interface state
    has_wan: bool = false,
    has_lan: bool = false,

    // Interface statistics
    wan_stats: IfaceStats = .{},
    lan_stats: IfaceStats = .{},

    // ARP tables
    wan_arp: [arp.TABLE_SIZE]arp.ArpEntry = [_]arp.ArpEntry{arp.empty} ** arp.TABLE_SIZE,
    lan_arp: [arp.TABLE_SIZE]arp.ArpEntry = [_]arp.ArpEntry{arp.empty} ** arp.TABLE_SIZE,

    // NAT table
    nat_table: [nat.TABLE_SIZE]nat.NatEntry = [_]nat.NatEntry{nat.empty} ** nat.TABLE_SIZE,
    next_nat_port: u16 = 10000,

    // Port forwarding
    port_forwards: [firewall.PORT_FWD_SIZE]firewall.PortForward = [_]firewall.PortForward{firewall.empty_fwd} ** firewall.PORT_FWD_SIZE,

    // Firewall rules
    firewall_rules: [firewall.RULES_SIZE]firewall.FirewallRule = [_]firewall.FirewallRule{firewall.empty_rule} ** firewall.RULES_SIZE,

    // DNS relay
    dns_relays: [dns.RELAY_SIZE]dns.DnsRelay = [_]dns.DnsRelay{dns.empty} ** dns.RELAY_SIZE,
    next_dns_id: u16 = 1,
    upstream_dns: [4]u8 = .{ 10, 0, 2, 1 },

    // DHCP server
    dhcp_leases: [dhcp_server.TABLE_SIZE]dhcp_server.DhcpLease = [_]dhcp_server.DhcpLease{dhcp_server.empty} ** dhcp_server.TABLE_SIZE,
    dhcp_next_ip: u8 = 100,

    // DHCP client
    dhcp_client_state: dhcp_client.DhcpClientState = .idle,
    dhcp_client_xid: u32 = 0x5A470001,
    dhcp_server_ip: [4]u8 = .{ 0, 0, 0, 0 },
    dhcp_offered_ip: [4]u8 = .{ 0, 0, 0, 0 },
    dhcp_client_start_ns: u64 = 0,
    wan_ip_static: bool = true,

    // Ping state
    ping_state: ping_mod.PingState = .idle,
    ping_target_ip: [4]u8 = .{ 0, 0, 0, 0 },
    ping_target_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
    ping_iface: Interface = .wan,
    ping_seq: u16 = 0,
    ping_start_ns: u64 = 0,
    ping_count: u8 = 0,
    ping_received: u8 = 0,

    // Fragment tracking
    frag_table: [frag.TABLE_SIZE]frag.FragEntry = [_]frag.FragEntry{frag.empty} ** frag.TABLE_SIZE,

    // Periodic maintenance
    last_maintenance_ns: u64 = 0,

    // ── Accessor methods ────────────────────────────────────────────────

    pub fn ifaceMac(self: *RouterContext, iface: Interface) *[6]u8 {
        return if (iface == .wan) &self.wan_mac else &self.lan_mac;
    }

    pub fn ifaceIp(self: *RouterContext, iface: Interface) *[4]u8 {
        return if (iface == .wan) &self.wan_ip else &self.lan_ip;
    }

    pub fn ifaceChan(self: *RouterContext, iface: Interface) *channel_mod.Channel {
        if (iface == .wan) return &self.wan_chan;
        return &(self.lan_chan orelse unreachable);
    }

    pub fn ifaceStats(self: *RouterContext, iface: Interface) *IfaceStats {
        return if (iface == .wan) &self.wan_stats else &self.lan_stats;
    }

    pub fn arpTable(self: *RouterContext, iface: Interface) *[arp.TABLE_SIZE]arp.ArpEntry {
        return if (iface == .wan) &self.wan_arp else &self.lan_arp;
    }
};

// ── Helpers ─────────────────────────────────────────────────────────────

pub fn isInLanSubnet(ip: [4]u8) bool {
    return (ip[0] & lan_mask[0]) == (lan_subnet[0] & lan_mask[0]) and
        (ip[1] & lan_mask[1]) == (lan_subnet[1] & lan_mask[1]) and
        (ip[2] & lan_mask[2]) == (lan_subnet[2] & lan_mask[2]) and
        (ip[3] & lan_mask[3]) == (lan_subnet[3] & lan_mask[3]);
}

fn handleIcmp(ctx: *RouterContext, iface: Interface, pkt: []u8, len: u32) ?[]u8 {
    if (len < 34) return null;
    if (pkt[23] != 1) return null;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const icmp_start = 14 + ip_hdr_len;
    if (icmp_start + 8 > len) return null;
    if (pkt[icmp_start] != 8) return null;

    const my_mac = ctx.ifaceMac(iface);

    @memcpy(pkt[0..6], pkt[6..12]);
    @memcpy(pkt[6..12], my_mac);

    var tmp: [4]u8 = undefined;
    @memcpy(&tmp, pkt[26..30]);
    @memcpy(pkt[26..30], pkt[30..34]);
    @memcpy(pkt[30..34], &tmp);

    pkt[icmp_start] = 0;
    pkt[icmp_start + 2] = 0;
    pkt[icmp_start + 3] = 0;
    const cs = util.computeChecksum(pkt[icmp_start..len]);
    pkt[icmp_start + 2] = @truncate(cs >> 8);
    pkt[icmp_start + 3] = @truncate(cs);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = util.computeChecksum(pkt[14..][0..ip_hdr_len]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    return pkt[0..len];
}

// ── Periodic maintenance ────────────────────────────────────────────────

fn periodicMaintenance(ctx: *RouterContext) void {
    const ts = util.now();
    if (ts -| ctx.last_maintenance_ns < MAINTENANCE_INTERVAL_NS) return;
    ctx.last_maintenance_ns = ts;

    arp.expire(&ctx.wan_arp);
    arp.expire(&ctx.lan_arp);
    nat.expire(&ctx.nat_table);
    frag.expire(&ctx.frag_table);
    dhcp_client.tick(ctx);
}

// ── Packet dispatch ─────────────────────────────────────────────────────

fn processPacket(ctx: *RouterContext, iface: Interface, pkt: []u8, len: u32) void {
    if (len < 14) return;

    const stats = ctx.ifaceStats(iface);
    stats.rx_packets += 1;
    stats.rx_bytes += len;

    const ethertype = util.readU16Be(pkt[12..14]);

    if (ethertype == 0x0806) {
        if (len >= 42) {
            var sender_mac: [6]u8 = undefined;
            var sender_ip: [4]u8 = undefined;
            @memcpy(&sender_mac, pkt[22..28]);
            @memcpy(&sender_ip, pkt[28..32]);
            arp.learn(ctx.arpTable(iface), sender_ip, sender_mac);

            if (ctx.ping_state == .arp_pending and ctx.ping_iface == iface) {
                if (arp.lookup(ctx.arpTable(iface), ctx.ping_target_ip)) |mac| {
                    @memcpy(&ctx.ping_target_mac, &mac);
                    ping_mod.sendEchoRequest(ctx);
                }
            }
        }
        if (arp.handle(ctx, iface, pkt, len)) |reply| {
            stats.tx_packets += 1;
            stats.tx_bytes += reply.len;
            _ = ctx.ifaceChan(iface).send(reply);
        }
    } else if (ethertype == 0x0800 and len >= 34) {
        var src_ip_fw: [4]u8 = undefined;
        @memcpy(&src_ip_fw, pkt[26..30]);

        if (iface == .wan and len >= 34) {
            const protocol_fw = pkt[23];
            var dst_port_fw: u16 = 0;
            if (protocol_fw == 6 or protocol_fw == 17) {
                const ip_hdr_len_fw: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
                const ts_fw = 14 + ip_hdr_len_fw;
                if (ts_fw + 4 <= len) {
                    dst_port_fw = util.readU16Be(pkt[ts_fw + 2 ..][0..2]);
                }
            }
            if (firewall.check(&ctx.firewall_rules, src_ip_fw, protocol_fw, dst_port_fw) == .block) {
                stats.rx_dropped += 1;
                return;
            }
        }

        var dst_ip: [4]u8 = undefined;
        @memcpy(&dst_ip, pkt[30..34]);

        const my_ip = ctx.ifaceIp(iface);
        const is_broadcast = dst_ip[0] == 255 and dst_ip[1] == 255 and dst_ip[2] == 255 and dst_ip[3] == 255;
        const is_for_me = util.eql(&dst_ip, my_ip) or util.eql(&dst_ip, &lan_broadcast) or is_broadcast;

        if (is_for_me) {
            if (pkt[23] == 17) {
                const ip_hdr_len_dhcp: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
                const udp_start_dhcp = 14 + ip_hdr_len_dhcp;
                if (udp_start_dhcp + 4 <= len) {
                    const udp_dst = util.readU16Be(pkt[udp_start_dhcp + 2 ..][0..2]);
                    if (udp_dst == 68 and iface == .wan) {
                        dhcp_client.handleResponse(ctx, pkt, len);
                        return;
                    }
                    if (udp_dst == 67 and iface == .lan) {
                        dhcp_server.handle(ctx, pkt, len);
                        return;
                    }
                    if (udp_dst == dns.DNS_PORT) {
                        if (iface == .lan) {
                            dns.handleFromLan(ctx, pkt, len);
                        }
                        return;
                    }
                }
            }
            ping_mod.handleEchoReply(ctx, pkt, len);
            if (handleIcmp(ctx, iface, pkt, len)) |reply| {
                stats.tx_packets += 1;
                stats.tx_bytes += reply.len;
                _ = ctx.ifaceChan(iface).send(reply);
            } else if (iface == .wan and ctx.has_lan) {
                nat.forwardWanToLan(ctx, pkt, len);
            }
        } else if (iface == .wan and ctx.has_lan) {
            if (pkt[23] == 17) {
                const ip_hdr_len_dns: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
                const udp_start_dns = 14 + ip_hdr_len_dns;
                if (udp_start_dns + 4 <= len) {
                    const udp_src_dns = util.readU16Be(pkt[udp_start_dns..][0..2]);
                    if (udp_src_dns == dns.DNS_PORT) {
                        dns.handleFromWan(ctx, pkt, len);
                        return;
                    }
                }
            }
            if (firewall.handlePortForward(ctx, pkt, len)) return;
            nat.forwardWanToLan(ctx, pkt, len);
        } else if (iface == .lan and ctx.has_wan) {
            if (pkt[23] == 17) {
                const ip_hdr_len_dns2: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
                const udp_start_dns2 = 14 + ip_hdr_len_dns2;
                if (udp_start_dns2 + 4 <= len) {
                    const udp_dst_dns = util.readU16Be(pkt[udp_start_dns2 + 2 ..][0..2]);
                    if (udp_dst_dns == dns.DNS_PORT) {
                        dns.handleFromLan(ctx, pkt, len);
                        return;
                    }
                }
            }
            nat.forwardLanToWan(ctx, pkt, len);
        }
    }
}

// ── Console commands ────────────────────────────────────────────────────

fn handleConsoleCommand(ctx: *RouterContext, data: []const u8) void {
    var chan = &(ctx.console_chan orelse return);
    if (util.eql(data, "status")) {
        var resp: [256]u8 = undefined;
        var pos: usize = 0;
        pos = util.appendStr(&resp, pos, "WAN: ");
        pos = util.appendIp(&resp, pos, ctx.wan_ip);
        pos = util.appendStr(&resp, pos, " (");
        pos = util.appendMac(&resp, pos, ctx.wan_mac);
        pos = util.appendStr(&resp, pos, ")");
        if (ctx.has_lan) {
            pos = util.appendStr(&resp, pos, "\nLAN: ");
            pos = util.appendIp(&resp, pos, ctx.lan_ip);
            pos = util.appendStr(&resp, pos, " (");
            pos = util.appendMac(&resp, pos, ctx.lan_mac);
            pos = util.appendStr(&resp, pos, ")");
        }
        _ = chan.send(resp[0..pos]);
    } else if (util.startsWith(data, "ping ")) {
        if (ctx.ping_state != .idle) {
            _ = chan.send("ping: already in progress");
            return;
        }
        if (util.parseIp(data[5..])) |ip| {
            ctx.ping_target_ip = ip;
            ctx.ping_seq = 0;
            ctx.ping_count = 0;
            ctx.ping_received = 0;
            ctx.ping_iface = if (isInLanSubnet(ip)) .lan else .wan;

            if (arp.lookup(ctx.arpTable(ctx.ping_iface), ip)) |mac| {
                @memcpy(&ctx.ping_target_mac, &mac);
                ping_mod.sendEchoRequest(ctx);
            } else {
                ctx.ping_state = .arp_pending;
                ctx.ping_start_ns = util.now();
                arp.sendRequest(ctx, ctx.ping_iface, ip);
            }
        } else {
            _ = chan.send("ping: invalid IP address");
        }
    } else if (util.eql(data, "arp")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        var count: u32 = 0;

        pos = util.appendStr(&resp, pos, "WAN ARP:");
        for (&ctx.wan_arp) |*e| {
            if (e.valid) {
                pos = util.appendStr(&resp, pos, "\n  ");
                pos = util.appendIp(&resp, pos, e.ip);
                pos = util.appendStr(&resp, pos, " -> ");
                pos = util.appendMac(&resp, pos, e.mac);
                count += 1;
            }
        }
        if (ctx.has_lan) {
            pos = util.appendStr(&resp, pos, "\nLAN ARP:");
            for (&ctx.lan_arp) |*e| {
                if (e.valid) {
                    pos = util.appendStr(&resp, pos, "\n  ");
                    pos = util.appendIp(&resp, pos, e.ip);
                    pos = util.appendStr(&resp, pos, " -> ");
                    pos = util.appendMac(&resp, pos, e.mac);
                    count += 1;
                }
            }
        }
        _ = chan.send(resp[0..pos]);
        var summary: [64]u8 = undefined;
        var spos: usize = 0;
        spos = util.appendStr(&summary, spos, "--- ");
        spos = util.appendDec(&summary, spos, count);
        spos = util.appendStr(&summary, spos, " entries ---");
        _ = chan.send(summary[0..spos]);
    } else if (util.eql(data, "nat")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        var count: u32 = 0;
        for (&ctx.nat_table) |*e| {
            if (e.valid) {
                if (count > 0 and pos < resp.len - 1) {
                    resp[pos] = '\n';
                    pos += 1;
                }
                const proto_str: []const u8 = switch (e.protocol) {
                    .icmp => "icmp",
                    .tcp => "tcp",
                    .udp => "udp",
                };
                pos = util.appendStr(&resp, pos, proto_str);
                pos = util.appendStr(&resp, pos, " ");
                pos = util.appendIp(&resp, pos, e.lan_ip);
                pos = util.appendStr(&resp, pos, ":");
                pos = util.appendDec(&resp, pos, e.lan_port);
                pos = util.appendStr(&resp, pos, " -> :");
                pos = util.appendDec(&resp, pos, e.wan_port);
                count += 1;
            }
        }
        if (count == 0) {
            _ = chan.send("nat table: empty");
        } else {
            _ = chan.send(resp[0..pos]);
        }
        var summary: [64]u8 = undefined;
        var spos: usize = 0;
        spos = util.appendStr(&summary, spos, "--- ");
        spos = util.appendDec(&summary, spos, count);
        spos = util.appendStr(&summary, spos, " NAT entries ---");
        _ = chan.send(summary[0..spos]);
    } else if (util.eql(data, "leases")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        var count: u32 = 0;
        for (&ctx.dhcp_leases) |*l| {
            if (l.valid) {
                if (count > 0 and pos < resp.len - 1) {
                    resp[pos] = '\n';
                    pos += 1;
                }
                pos = util.appendMac(&resp, pos, l.mac);
                pos = util.appendStr(&resp, pos, " -> ");
                pos = util.appendIp(&resp, pos, l.ip);
                count += 1;
            }
        }
        if (count == 0) {
            _ = chan.send("dhcp leases: empty");
        } else {
            _ = chan.send(resp[0..pos]);
        }
        var summary: [64]u8 = undefined;
        var spos: usize = 0;
        spos = util.appendStr(&summary, spos, "--- ");
        spos = util.appendDec(&summary, spos, count);
        spos = util.appendStr(&summary, spos, " leases ---");
        _ = chan.send(summary[0..spos]);
    } else if (util.eql(data, "ifstat")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        pos = util.appendStr(&resp, pos, "WAN: rx=");
        pos = util.appendDec(&resp, pos, ctx.wan_stats.rx_packets);
        pos = util.appendStr(&resp, pos, " (");
        pos = util.appendDec(&resp, pos, ctx.wan_stats.rx_bytes);
        pos = util.appendStr(&resp, pos, "B) tx=");
        pos = util.appendDec(&resp, pos, ctx.wan_stats.tx_packets);
        pos = util.appendStr(&resp, pos, " (");
        pos = util.appendDec(&resp, pos, ctx.wan_stats.tx_bytes);
        pos = util.appendStr(&resp, pos, "B) drop=");
        pos = util.appendDec(&resp, pos, ctx.wan_stats.rx_dropped);
        if (ctx.has_lan) {
            pos = util.appendStr(&resp, pos, "\nLAN: rx=");
            pos = util.appendDec(&resp, pos, ctx.lan_stats.rx_packets);
            pos = util.appendStr(&resp, pos, " (");
            pos = util.appendDec(&resp, pos, ctx.lan_stats.rx_bytes);
            pos = util.appendStr(&resp, pos, "B) tx=");
            pos = util.appendDec(&resp, pos, ctx.lan_stats.tx_packets);
            pos = util.appendStr(&resp, pos, " (");
            pos = util.appendDec(&resp, pos, ctx.lan_stats.tx_bytes);
            pos = util.appendStr(&resp, pos, "B) drop=");
            pos = util.appendDec(&resp, pos, ctx.lan_stats.rx_dropped);
        }
        _ = chan.send(resp[0..pos]);
    } else if (util.startsWith(data, "forward ")) {
        const args = data[8..];
        var proto: util.Protocol = .tcp;
        var rest = args;
        if (util.startsWith(rest, "tcp ")) {
            proto = .tcp;
            rest = rest[4..];
        } else if (util.startsWith(rest, "udp ")) {
            proto = .udp;
            rest = rest[4..];
        } else {
            _ = chan.send("forward: usage: forward <tcp|udp> <wan_port> <lan_ip> <lan_port>");
            return;
        }
        if (util.parsePortIpPort(rest)) |result| {
            if (firewall.portFwdAdd(&ctx.port_forwards, proto, result.port1, result.ip, result.port2)) {
                _ = chan.send("forward: rule added");
            } else {
                _ = chan.send("forward: table full");
            }
        } else {
            _ = chan.send("forward: invalid arguments");
        }
    } else if (util.startsWith(data, "block ")) {
        if (util.parseIp(data[6..])) |ip| {
            for (&ctx.firewall_rules) |*r| {
                if (!r.valid) {
                    r.* = .{
                        .valid = true, .action = .block,
                        .src_ip = ip, .src_mask = .{ 255, 255, 255, 255 },
                        .protocol = 0, .dst_port = 0,
                    };
                    _ = chan.send("firewall: block rule added");
                    return;
                }
            }
            _ = chan.send("firewall: rule table full");
        } else {
            _ = chan.send("block: invalid IP");
        }
    } else if (util.startsWith(data, "allow ")) {
        if (util.parseIp(data[6..])) |ip| {
            for (&ctx.firewall_rules) |*r| {
                if (r.valid and r.src_ip[0] == ip[0] and r.src_ip[1] == ip[1] and
                    r.src_ip[2] == ip[2] and r.src_ip[3] == ip[3])
                {
                    r.valid = false;
                    _ = chan.send("firewall: rule removed");
                    return;
                }
            }
            _ = chan.send("firewall: no matching rule found");
        } else {
            _ = chan.send("allow: invalid IP");
        }
    } else if (util.eql(data, "rules")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        var count: u32 = 0;

        pos = util.appendStr(&resp, pos, "Firewall rules:");
        for (&ctx.firewall_rules) |*r| {
            if (r.valid) {
                pos = util.appendStr(&resp, pos, "\n  ");
                pos = util.appendStr(&resp, pos, if (r.action == .block) "BLOCK " else "ALLOW ");
                pos = util.appendIp(&resp, pos, r.src_ip);
                if (r.protocol != 0) {
                    pos = util.appendStr(&resp, pos, " proto=");
                    pos = util.appendDec(&resp, pos, r.protocol);
                }
                if (r.dst_port != 0) {
                    pos = util.appendStr(&resp, pos, " port=");
                    pos = util.appendDec(&resp, pos, r.dst_port);
                }
                count += 1;
            }
        }

        pos = util.appendStr(&resp, pos, "\nPort forwards:");
        for (&ctx.port_forwards) |*f| {
            if (f.valid) {
                pos = util.appendStr(&resp, pos, "\n  ");
                pos = util.appendStr(&resp, pos, if (f.protocol == .tcp) "tcp" else "udp");
                pos = util.appendStr(&resp, pos, " :");
                pos = util.appendDec(&resp, pos, f.wan_port);
                pos = util.appendStr(&resp, pos, " -> ");
                pos = util.appendIp(&resp, pos, f.lan_ip);
                pos = util.appendStr(&resp, pos, ":");
                pos = util.appendDec(&resp, pos, f.lan_port);
                count += 1;
            }
        }
        _ = chan.send(resp[0..pos]);
        var summary: [64]u8 = undefined;
        var spos: usize = 0;
        spos = util.appendStr(&summary, spos, "--- ");
        spos = util.appendDec(&summary, spos, count);
        spos = util.appendStr(&summary, spos, " rules ---");
        _ = chan.send(summary[0..spos]);
    } else if (util.eql(data, "dhcp-client")) {
        if (ctx.dhcp_client_state == .bound) {
            var resp: [128]u8 = undefined;
            var rp: usize = 0;
            rp = util.appendStr(&resp, rp, "DHCP client: bound to ");
            rp = util.appendIp(&resp, rp, ctx.wan_ip);
            rp = util.appendStr(&resp, rp, " (server ");
            rp = util.appendIp(&resp, rp, ctx.dhcp_server_ip);
            rp = util.appendStr(&resp, rp, ")");
            _ = chan.send(resp[0..rp]);
        } else if (ctx.dhcp_client_state == .idle) {
            ctx.wan_ip_static = false;
            dhcp_client.sendDiscover(ctx);
            _ = chan.send("DHCP client: discovering...");
        } else {
            _ = chan.send("DHCP client: in progress");
        }
    } else if (util.startsWith(data, "dns ")) {
        if (util.parseIp(data[4..])) |ip| {
            ctx.upstream_dns = ip;
            var resp: [64]u8 = undefined;
            var pos: usize = 0;
            pos = util.appendStr(&resp, pos, "DNS upstream set to ");
            pos = util.appendIp(&resp, pos, ip);
            _ = chan.send(resp[0..pos]);
        } else {
            _ = chan.send("dns: invalid IP");
        }
    } else {
        _ = chan.send("router: unknown command");
    }
}

// ── Channel setup helpers ───────────────────────────────────────────────

fn mapShmAsSideB(handle: u64, size: u64) ?channel_mod.Channel {
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();
    const vm = syscall.vm_reserve(0, size, vm_rights);
    if (vm.val < 0) return null;
    if (syscall.shm_map(handle, @intCast(vm.val), 0) != 0) return null;
    const header: *channel_mod.ChannelHeader = @ptrFromInt(vm.val2);
    return channel_mod.Channel.openAsSideB(header);
}

fn waitForMac(chan: *channel_mod.Channel) [6]u8 {
    var mac_buf: [64]u8 = undefined;
    while (true) {
        if (chan.recv(&mac_buf)) |len| {
            if (len == 6) {
                var mac: [6]u8 = undefined;
                @memcpy(&mac, mac_buf[0..6]);
                return mac;
            }
        }
        syscall.thread_yield();
    }
}

// ── Main ────────────────────────────────────────────────────────────────

pub fn main(perm_view_addr: u64) void {
    syscall.write("router: started\n");

    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("router: no command channel\n");
        return;
    };

    const wan_entry = cmd.requestConnection(shm_protocol.ServiceId.NIC_WAN) orelse {
        syscall.write("router: WAN NIC not allowed\n");
        return;
    };
    if (!cmd.waitForConnection(wan_entry)) {
        syscall.write("router: WAN connection failed\n");
        return;
    }
    syscall.write("router: WAN NIC connected\n");

    var has_lan_connection = false;
    const lan_entry = cmd.requestConnection(shm_protocol.ServiceId.NIC_LAN);
    if (lan_entry) |le| {
        if (cmd.waitForConnection(le)) {
            has_lan_connection = true;
            syscall.write("router: LAN NIC connected\n");
        }
    }

    const expected_data_shms: u32 = if (has_lan_connection) 2 else 1;

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    var data_handles: [4]u64 = .{ 0, 0, 0, 0 };
    var data_sizes: [4]u64 = .{ 0, 0, 0, 0 };
    var data_count: u32 = 0;
    while (data_count < expected_data_shms) {
        data_count = 0;
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 > shm_protocol.COMMAND_SHM_SIZE and data_count < 4)
            {
                data_handles[data_count] = e.handle;
                data_sizes[data_count] = e.field0;
                data_count += 1;
            }
        }
        if (data_count < expected_data_shms) syscall.thread_yield();
    }

    var ctx = RouterContext{};

    ctx.wan_chan = mapShmAsSideB(data_handles[0], data_sizes[0]) orelse {
        syscall.write("router: WAN channel open failed\n");
        return;
    };
    ctx.has_wan = true;

    ctx.wan_mac = waitForMac(&ctx.wan_chan);
    syscall.write("router: WAN MAC learned\n");

    if (has_lan_connection and data_count >= 2) {
        if (mapShmAsSideB(data_handles[1], data_sizes[1])) |ch| {
            ctx.lan_chan = ch;
            ctx.has_lan = true;
            ctx.lan_mac = waitForMac(&(ctx.lan_chan.?));
            syscall.write("router: LAN MAC learned\n");
        }
    }

    arp.sendRequest(&ctx, .wan, .{ 10, 0, 2, 1 });
    syscall.write("router: sent ARP request on WAN\n");

    while (true) {
        if (ctx.console_chan == null) {
            var shm_idx: u32 = 0;
            for (view) |*e| {
                if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                    e.field0 > shm_protocol.COMMAND_SHM_SIZE)
                {
                    if (shm_idx < data_count) {
                        shm_idx += 1;
                        continue;
                    }
                    const vm_rights_con = (perms.VmReservationRights{
                        .read = true, .write = true, .shareable = true,
                    }).bits();
                    const con_vm = syscall.vm_reserve(0, e.field0, vm_rights_con);
                    if (con_vm.val >= 0) {
                        if (syscall.shm_map(e.handle, @intCast(con_vm.val), 0) == 0) {
                            const con_header: *channel_mod.ChannelHeader = @ptrFromInt(con_vm.val2);
                            ctx.console_chan = channel_mod.Channel.initAsSideA(con_header, @truncate(e.field0));
                            syscall.write("router: console channel connected\n");
                        }
                    }
                    break;
                }
            }
        }

        if (ctx.console_chan) |*chan| {
            var cmd_buf: [256]u8 = undefined;
            if (chan.recv(&cmd_buf)) |len| {
                handleConsoleCommand(&ctx, cmd_buf[0..len]);
            }
        }

        var pkt_buf: [2048]u8 = undefined;
        if (ctx.wan_chan.recv(&pkt_buf)) |len| {
            processPacket(&ctx, .wan, &pkt_buf, len);
        }

        if (ctx.lan_chan) |*ch| {
            var lan_pkt: [2048]u8 = undefined;
            if (ch.recv(&lan_pkt)) |len| {
                processPacket(&ctx, .lan, &lan_pkt, len);
            }
        }

        ping_mod.checkTimeout(&ctx);
        periodicMaintenance(&ctx);
        syscall.thread_yield();
    }
}
