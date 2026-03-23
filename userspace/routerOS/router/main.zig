const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const ARP_TABLE_SIZE = 16;
const NAT_TABLE_SIZE = 128;
const DHCP_LEASE_TABLE_SIZE = 32;

// ── Interface state ─────────────────────────────────────────────────────

const Interface = enum { wan, lan };

var wan_chan: channel_mod.Channel = undefined;
var lan_chan: ?channel_mod.Channel = null;
var console_chan: ?channel_mod.Channel = null;

var wan_mac: [6]u8 = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
var lan_mac: [6]u8 = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 };
var wan_ip: [4]u8 = .{ 10, 0, 2, 15 };
var lan_ip: [4]u8 = .{ 192, 168, 1, 1 };
const lan_subnet: [4]u8 = .{ 192, 168, 1, 0 };
const lan_mask: [4]u8 = .{ 255, 255, 255, 0 };
const lan_broadcast: [4]u8 = .{ 192, 168, 1, 255 };

var has_wan: bool = false;
var has_lan: bool = false;

// ── Interface statistics ────────────────────────────────────────────────

const IfaceStats = struct {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    rx_dropped: u64,
};

var wan_stats: IfaceStats = .{ .rx_packets = 0, .rx_bytes = 0, .tx_packets = 0, .tx_bytes = 0, .rx_dropped = 0 };
var lan_stats: IfaceStats = .{ .rx_packets = 0, .rx_bytes = 0, .tx_packets = 0, .tx_bytes = 0, .rx_dropped = 0 };

fn ifaceStats(iface: Interface) *IfaceStats {
    return if (iface == .wan) &wan_stats else &lan_stats;
}

// ── Port forwarding table ───────────────────────────────────────────────

const PORT_FWD_SIZE = 16;

const PortForward = struct {
    valid: bool,
    protocol: Protocol,
    wan_port: u16,
    lan_ip: [4]u8,
    lan_port: u16,
};

const empty_fwd = PortForward{ .valid = false, .protocol = .tcp, .wan_port = 0, .lan_ip = .{ 0, 0, 0, 0 }, .lan_port = 0 };
var port_forwards: [PORT_FWD_SIZE]PortForward = [_]PortForward{empty_fwd} ** PORT_FWD_SIZE;

fn portFwdLookup(proto: Protocol, wan_port: u16) ?*const PortForward {
    for (&port_forwards) |*f| {
        if (f.valid and f.protocol == proto and f.wan_port == wan_port) return f;
    }
    return null;
}

fn portFwdAdd(proto: Protocol, wan_port: u16, lip: [4]u8, lport: u16) bool {
    for (&port_forwards) |*f| {
        if (!f.valid) {
            f.* = .{ .valid = true, .protocol = proto, .wan_port = wan_port, .lan_ip = lip, .lan_port = lport };
            return true;
        }
    }
    return false;
}

// ── Firewall rules ──────────────────────────────────────────────────────

const FIREWALL_RULES_SIZE = 32;

const FirewallAction = enum { allow, block };

const FirewallRule = struct {
    valid: bool,
    action: FirewallAction,
    src_ip: [4]u8,
    src_mask: [4]u8,
    protocol: u8,
    dst_port: u16,
};

const empty_rule = FirewallRule{
    .valid = false, .action = .block,
    .src_ip = .{ 0, 0, 0, 0 }, .src_mask = .{ 0, 0, 0, 0 },
    .protocol = 0, .dst_port = 0,
};
var firewall_rules: [FIREWALL_RULES_SIZE]FirewallRule = [_]FirewallRule{empty_rule} ** FIREWALL_RULES_SIZE;

fn firewallCheck(src_ip: [4]u8, protocol: u8, dst_port: u16) FirewallAction {
    for (&firewall_rules) |*r| {
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

// ── DNS relay state ─────────────────────────────────────────────────────

const DNS_RELAY_SIZE = 32;
const DNS_PORT: u16 = 53;
var upstream_dns: [4]u8 = .{ 10, 0, 2, 1 };

const DnsRelay = struct {
    valid: bool,
    client_ip: [4]u8,
    client_port: u16,
    query_id: u16,
    relay_id: u16,
    timestamp_ns: u64,
};

const empty_dns = DnsRelay{
    .valid = false, .client_ip = .{ 0, 0, 0, 0 },
    .client_port = 0, .query_id = 0, .relay_id = 0, .timestamp_ns = 0,
};
var dns_relays: [DNS_RELAY_SIZE]DnsRelay = [_]DnsRelay{empty_dns} ** DNS_RELAY_SIZE;
var next_dns_id: u16 = 1;

// ── ARP tables ──────────────────────────────────────────────────────────

const ArpEntry = struct {
    ip: [4]u8,
    mac: [6]u8,
    valid: bool,
};

const empty_arp = ArpEntry{ .ip = .{ 0, 0, 0, 0 }, .mac = .{ 0, 0, 0, 0, 0, 0 }, .valid = false };
var wan_arp: [ARP_TABLE_SIZE]ArpEntry = [_]ArpEntry{empty_arp} ** ARP_TABLE_SIZE;
var lan_arp: [ARP_TABLE_SIZE]ArpEntry = [_]ArpEntry{empty_arp} ** ARP_TABLE_SIZE;

fn arpTable(iface: Interface) *[ARP_TABLE_SIZE]ArpEntry {
    return if (iface == .wan) &wan_arp else &lan_arp;
}

fn arpLookup(table: *[ARP_TABLE_SIZE]ArpEntry, ip: [4]u8) ?[6]u8 {
    for (table) |*e| {
        if (e.valid and eql(&e.ip, &ip)) return e.mac;
    }
    return null;
}

fn arpLearn(table: *[ARP_TABLE_SIZE]ArpEntry, ip: [4]u8, mac: [6]u8) void {
    for (table) |*e| {
        if (e.valid and eql(&e.ip, &ip)) {
            @memcpy(&e.mac, &mac);
            return;
        }
    }
    for (table) |*e| {
        if (!e.valid) {
            e.ip = ip;
            @memcpy(&e.mac, &mac);
            e.valid = true;
            return;
        }
    }
    table[0].ip = ip;
    @memcpy(&table[0].mac, &mac);
    table[0].valid = true;
}

// ── NAT table ───────────────────────────────────────────────────────────

const Protocol = enum(u8) { icmp = 1, tcp = 6, udp = 17 };

const NatEntry = struct {
    valid: bool,
    protocol: Protocol,
    lan_ip: [4]u8,
    lan_port: u16,
    wan_port: u16,
    timestamp_ns: u64,
};

const empty_nat = NatEntry{
    .valid = false, .protocol = .icmp,
    .lan_ip = .{ 0, 0, 0, 0 }, .lan_port = 0, .wan_port = 0, .timestamp_ns = 0,
};
var nat_table: [NAT_TABLE_SIZE]NatEntry = [_]NatEntry{empty_nat} ** NAT_TABLE_SIZE;
var next_nat_port: u16 = 10000;
const NAT_TIMEOUT_NS: u64 = 120_000_000_000;

fn now() u64 {
    return @bitCast(syscall.clock_gettime());
}

fn natLookupOutbound(proto: Protocol, lip: [4]u8, lport: u16) ?*NatEntry {
    for (&nat_table) |*e| {
        if (e.valid and e.protocol == proto and eql(&e.lan_ip, &lip) and e.lan_port == lport) {
            e.timestamp_ns = now();
            return e;
        }
    }
    return null;
}

fn natCreateOutbound(proto: Protocol, lip: [4]u8, lport: u16) ?*NatEntry {
    const ts = now();
    var oldest_idx: usize = 0;
    var oldest_ts: u64 = ts;
    for (&nat_table, 0..) |*e, i| {
        if (!e.valid) {
            e.* = .{ .valid = true, .protocol = proto, .lan_ip = lip,
                .lan_port = lport, .wan_port = next_nat_port, .timestamp_ns = ts };
            next_nat_port +%= 1;
            if (next_nat_port < 10000) next_nat_port = 10000;
            return e;
        }
        if (e.timestamp_ns < oldest_ts) {
            oldest_ts = e.timestamp_ns;
            oldest_idx = i;
        }
    }
    nat_table[oldest_idx] = .{ .valid = true, .protocol = proto, .lan_ip = lip,
        .lan_port = lport, .wan_port = next_nat_port, .timestamp_ns = ts };
    next_nat_port +%= 1;
    if (next_nat_port < 10000) next_nat_port = 10000;
    return &nat_table[oldest_idx];
}

fn natLookupInbound(proto: Protocol, wport: u16) ?*NatEntry {
    for (&nat_table) |*e| {
        if (e.valid and e.protocol == proto and e.wan_port == wport) {
            e.timestamp_ns = now();
            return e;
        }
    }
    return null;
}

// ── DHCP server (LAN side) ──────────────────────────────────────────────

const DhcpLease = struct {
    mac: [6]u8,
    ip: [4]u8,
    valid: bool,
};

const empty_lease = DhcpLease{ .mac = .{ 0, 0, 0, 0, 0, 0 }, .ip = .{ 0, 0, 0, 0 }, .valid = false };
var dhcp_leases: [DHCP_LEASE_TABLE_SIZE]DhcpLease = [_]DhcpLease{empty_lease} ** DHCP_LEASE_TABLE_SIZE;
var dhcp_next_ip: u8 = 100;

fn dhcpFindLease(mac: [6]u8) ?[4]u8 {
    for (&dhcp_leases) |*l| {
        if (l.valid and eql(&l.mac, &mac)) return l.ip;
    }
    return null;
}

fn dhcpAllocateLease(mac: [6]u8) ?[4]u8 {
    if (dhcpFindLease(mac)) |ip| return ip;
    for (&dhcp_leases) |*l| {
        if (!l.valid) {
            l.ip = .{ 192, 168, 1, dhcp_next_ip };
            @memcpy(&l.mac, &mac);
            l.valid = true;
            dhcp_next_ip +%= 1;
            if (dhcp_next_ip < 100) dhcp_next_ip = 100;
            return l.ip;
        }
    }
    return null;
}

// DHCP message types
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

fn handleDhcpServer(pkt: []const u8, len: u32) void {
    if (!has_lan) return;
    if (len < 282) return;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;

    const src_port = readU16Be(pkt[udp_start..][0..2]);
    const dst_port = readU16Be(pkt[udp_start + 2 ..][0..2]);
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
        const offer_ip = dhcpAllocateLease(client_mac) orelse return;
        const response_type: u8 = if (msg_type == DHCP_DISCOVER) DHCP_OFFER else DHCP_ACK;
        sendDhcpResponse(pkt[dhcp_start..], client_mac, offer_ip, response_type, @truncate(len - dhcp_start));
    }
}

fn sendDhcpResponse(request: []const u8, client_mac: [6]u8, offer_ip: [4]u8, msg_type: u8, req_len: u32) void {
    _ = req_len;
    var pkt: [600]u8 = undefined;
    @memset(&pkt, 0);

    @memset(pkt[0..6], 0xFF);
    @memcpy(pkt[6..12], &lan_mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    pkt[15] = 0x00;
    pkt[22] = 64;
    pkt[23] = 17;
    @memcpy(pkt[26..30], &lan_ip);
    @memset(pkt[30..34], 0xFF);

    const udp_start: usize = 34;
    writeU16Be(pkt[udp_start..][0..2], 67);
    writeU16Be(pkt[udp_start + 2 ..][0..2], 68);

    const dhcp_start: usize = udp_start + 8;
    pkt[dhcp_start] = 2;
    pkt[dhcp_start + 1] = 1;
    pkt[dhcp_start + 2] = 6;
    pkt[dhcp_start + 3] = 0;
    @memcpy(pkt[dhcp_start + 4 ..][0..4], request[4..8]);
    @memcpy(pkt[dhcp_start + 16 ..][0..4], &offer_ip);
    @memcpy(pkt[dhcp_start + 20 ..][0..4], &lan_ip);
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
    @memcpy(pkt[opt + 2 ..][0..4], &lan_mask);
    opt += 6;

    pkt[opt] = 3;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &lan_ip);
    opt += 6;

    pkt[opt] = 6;
    pkt[opt + 1] = 4;
    @memcpy(pkt[opt + 2 ..][0..4], &lan_ip);
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
    @memcpy(pkt[opt + 2 ..][0..4], &lan_ip);
    opt += 6;

    pkt[opt] = 255;
    opt += 1;

    const total_dhcp = opt - dhcp_start;
    const udp_len: u16 = @truncate(8 + total_dhcp);
    writeU16Be(pkt[udp_start + 4 ..][0..2], udp_len);

    const ip_total: u16 = @truncate(20 + udp_len);
    writeU16Be(pkt[16..18], ip_total);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = computeChecksum(pkt[14..34]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    const total_len = 14 + ip_total;
    const send_len = if (total_len < 60) @as(usize, 60) else @as(usize, @intCast(total_len));
    if (lan_chan) |*ch| {
        _ = ch.send(pkt[0..send_len]);
    }
}

// ── Ping state machine ──────────────────────────────────────────────────

const PingState = enum { idle, arp_pending, echo_sent };

var ping_state: PingState = .idle;
var ping_target_ip: [4]u8 = .{ 0, 0, 0, 0 };
var ping_target_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
var ping_iface: Interface = .wan;
var ping_seq: u16 = 0;
const ping_id: u16 = 0x5A47;
var ping_start_ns: u64 = 0;
const ping_timeout_ns: u64 = 3_000_000_000;
var ping_count: u8 = 0;
const ping_total: u8 = 4;
var ping_received: u8 = 0;

// ── String helpers ──────────────────────────────────────────────────────

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn startsWith(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return eql(haystack[0..prefix.len], prefix);
}

fn appendStr(buf: []u8, pos: usize, s: []const u8) usize {
    const end = @min(pos + s.len, buf.len);
    @memcpy(buf[pos..end], s[0..(end - pos)]);
    return end;
}

fn appendDec(buf: []u8, pos: usize, val: u64) usize {
    if (val == 0) {
        if (pos < buf.len) {
            buf[pos] = '0';
            return pos + 1;
        }
        return pos;
    }
    var tmp: [20]u8 = undefined;
    var v = val;
    var i: usize = 20;
    while (v > 0) {
        i -= 1;
        tmp[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    return appendStr(buf, pos, tmp[i..20]);
}

fn appendIp(buf: []u8, pos: usize, ip: [4]u8) usize {
    var p = pos;
    for (ip, 0..) |octet, idx| {
        p = appendDec(buf, p, octet);
        if (idx < 3) p = appendStr(buf, p, ".");
    }
    return p;
}

fn appendMac(buf: []u8, pos: usize, mac: [6]u8) usize {
    const hex_chars = "0123456789abcdef";
    var p = pos;
    for (mac, 0..) |byte, idx| {
        if (p + 2 > buf.len) break;
        buf[p] = hex_chars[byte >> 4];
        buf[p + 1] = hex_chars[byte & 0xf];
        p += 2;
        if (idx < 5) p = appendStr(buf, p, ":");
    }
    return p;
}

fn parseIp(s: []const u8) ?[4]u8 {
    var ip: [4]u8 = undefined;
    var octet: u16 = 0;
    var idx: usize = 0;
    var digits: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (digits == 0 or octet > 255 or idx >= 3) return null;
            ip[idx] = @truncate(octet);
            idx += 1;
            octet = 0;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            digits += 1;
        } else {
            return null;
        }
    }
    if (digits == 0 or octet > 255 or idx != 3) return null;
    ip[3] = @truncate(octet);
    return ip;
}

// ── Packet helpers ──────────────────────────────────────────────────────

fn readU16Be(buf: []const u8) u16 {
    return @as(u16, buf[0]) << 8 | buf[1];
}

fn writeU16Be(buf: []u8, val: u16) void {
    buf[0] = @truncate(val >> 8);
    buf[1] = @truncate(val);
}

fn computeChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, data[i]) << 8 | data[i + 1];
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @truncate(~sum);
}

fn isInLanSubnet(ip: [4]u8) bool {
    return (ip[0] & lan_mask[0]) == (lan_subnet[0] & lan_mask[0]) and
        (ip[1] & lan_mask[1]) == (lan_subnet[1] & lan_mask[1]) and
        (ip[2] & lan_mask[2]) == (lan_subnet[2] & lan_mask[2]) and
        (ip[3] & lan_mask[3]) == (lan_subnet[3] & lan_mask[3]);
}

fn ifaceMac(iface: Interface) *[6]u8 {
    return if (iface == .wan) &wan_mac else &lan_mac;
}

fn ifaceIp(iface: Interface) *[4]u8 {
    return if (iface == .wan) &wan_ip else &lan_ip;
}

fn ifaceChan(iface: Interface) *channel_mod.Channel {
    if (iface == .wan) return &wan_chan;
    return &(lan_chan orelse unreachable);
}

// ── ARP packet handling ─────────────────────────────────────────────────

fn sendArpRequestOn(iface: Interface, target_ip: [4]u8) void {
    var pkt: [60]u8 = undefined;
    @memset(&pkt, 0);
    @memset(pkt[0..6], 0xFF);
    @memcpy(pkt[6..12], ifaceMac(iface));
    pkt[12] = 0x08;
    pkt[13] = 0x06;
    pkt[14] = 0x00;
    pkt[15] = 0x01;
    pkt[16] = 0x08;
    pkt[17] = 0x00;
    pkt[18] = 0x06;
    pkt[19] = 0x04;
    pkt[20] = 0x00;
    pkt[21] = 0x01;
    @memcpy(pkt[22..28], ifaceMac(iface));
    @memcpy(pkt[28..32], ifaceIp(iface));
    @memset(pkt[32..38], 0);
    @memcpy(pkt[38..42], &target_ip);
    _ = ifaceChan(iface).send(&pkt);
}

fn handleArp(iface: Interface, pkt: []u8, len: u32) ?[]u8 {
    if (len < 42) return null;
    const arp_start = 14;
    if (readU16Be(pkt[arp_start..][0..2]) != 0x0001) return null;
    if (readU16Be(pkt[arp_start + 2 ..][0..2]) != 0x0800) return null;

    const my_ip = ifaceIp(iface);
    const my_mac = ifaceMac(iface);

    const opcode = readU16Be(pkt[arp_start + 6 ..][0..2]);
    if (opcode != 0x0001 and opcode != 0x0002) return null;

    if (opcode == 0x0001 and !eql(pkt[arp_start + 24 ..][0..4], my_ip)) return null;

    if (opcode == 0x0001) {
        @memcpy(pkt[0..6], pkt[6..12]);
        @memcpy(pkt[6..12], my_mac);
        writeU16Be(pkt[arp_start + 6 ..][0..2], 0x0002);

        var mac_tmp: [6]u8 = undefined;
        @memcpy(&mac_tmp, pkt[arp_start + 8 ..][0..6]);
        @memcpy(pkt[arp_start + 18 ..][0..6], &mac_tmp);
        @memcpy(pkt[arp_start + 8 ..][0..6], my_mac);

        var ip_tmp: [4]u8 = undefined;
        @memcpy(&ip_tmp, pkt[arp_start + 14 ..][0..4]);
        @memcpy(pkt[arp_start + 24 ..][0..4], &ip_tmp);
        @memcpy(pkt[arp_start + 14 ..][0..4], my_ip);

        if (len < 60) {
            @memset(pkt[42..60], 0);
            return pkt[0..60];
        }
        return pkt[0..len];
    }

    return null;
}

// ── ICMP handling ───────────────────────────────────────────────────────

fn handleIcmp(iface: Interface, pkt: []u8, len: u32) ?[]u8 {
    if (len < 34) return null;
    if (pkt[23] != 1) return null;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const icmp_start = 14 + ip_hdr_len;
    if (icmp_start + 8 > len) return null;
    if (pkt[icmp_start] != 8) return null;

    const my_mac = ifaceMac(iface);

    @memcpy(pkt[0..6], pkt[6..12]);
    @memcpy(pkt[6..12], my_mac);

    var tmp: [4]u8 = undefined;
    @memcpy(&tmp, pkt[26..30]);
    @memcpy(pkt[26..30], pkt[30..34]);
    @memcpy(pkt[30..34], &tmp);

    pkt[icmp_start] = 0;
    pkt[icmp_start + 2] = 0;
    pkt[icmp_start + 3] = 0;
    const cs = computeChecksum(pkt[icmp_start..len]);
    pkt[icmp_start + 2] = @truncate(cs >> 8);
    pkt[icmp_start + 3] = @truncate(cs);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = computeChecksum(pkt[14..][0..ip_hdr_len]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    return pkt[0..len];
}

// ── Outbound ping ───────────────────────────────────────────────────────

fn sendEchoRequest() void {
    var pkt: [98]u8 = undefined;
    @memset(&pkt, 0);

    const src_mac = ifaceMac(ping_iface);
    const src_ip = ifaceIp(ping_iface);

    @memcpy(pkt[0..6], &ping_target_mac);
    @memcpy(pkt[6..12], src_mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    writeU16Be(pkt[16..18], 84);
    writeU16Be(pkt[18..20], ping_id);
    pkt[22] = 64;
    pkt[23] = 1;
    @memcpy(pkt[26..30], src_ip);
    @memcpy(pkt[30..34], &ping_target_ip);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = computeChecksum(pkt[14..34]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    pkt[34] = 8;
    writeU16Be(pkt[38..40], ping_id);
    writeU16Be(pkt[40..42], ping_seq);

    pkt[36] = 0;
    pkt[37] = 0;
    const icmp_cs = computeChecksum(pkt[34..98]);
    pkt[36] = @truncate(icmp_cs >> 8);
    pkt[37] = @truncate(icmp_cs);

    ping_start_ns = now();
    ping_state = .echo_sent;
    _ = ifaceChan(ping_iface).send(&pkt);
}

fn handleEchoReply(pkt: []const u8, len: u32) void {
    if (ping_state != .echo_sent) return;
    if (len < 42) return;
    if (pkt[23] != 1) return;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const icmp_start = 14 + ip_hdr_len;
    if (icmp_start + 8 > len) return;
    if (pkt[icmp_start] != 0) return;

    const reply_id = readU16Be(pkt[icmp_start + 4 ..][0..2]);
    const reply_seq = readU16Be(pkt[icmp_start + 6 ..][0..2]);
    if (reply_id != ping_id or reply_seq != ping_seq) return;

    const rtt_us = (now() -| ping_start_ns) / 1000;
    ping_received += 1;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = appendStr(&resp, pos, "reply from ");
    pos = appendIp(&resp, pos, ping_target_ip);
    pos = appendStr(&resp, pos, ": seq=");
    pos = appendDec(&resp, pos, ping_seq);
    pos = appendStr(&resp, pos, " time=");
    pos = appendDec(&resp, pos, rtt_us);
    pos = appendStr(&resp, pos, "us");
    if (console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    ping_count += 1;
    if (ping_count >= ping_total) {
        sendPingSummary();
        ping_state = .idle;
    } else {
        ping_seq += 1;
        sendEchoRequest();
    }
}

fn sendPingSummary() void {
    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = appendStr(&resp, pos, "--- ping ");
    pos = appendIp(&resp, pos, ping_target_ip);
    pos = appendStr(&resp, pos, ": ");
    pos = appendDec(&resp, pos, ping_total);
    pos = appendStr(&resp, pos, " sent, ");
    pos = appendDec(&resp, pos, ping_received);
    pos = appendStr(&resp, pos, " received ---");
    if (console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }
}

fn checkPingTimeout() void {
    if (ping_state == .idle) return;
    if (now() -| ping_start_ns < ping_timeout_ns) return;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    if (ping_state == .arp_pending) {
        pos = appendStr(&resp, pos, "ping: ARP timeout for ");
        pos = appendIp(&resp, pos, ping_target_ip);
    } else {
        pos = appendStr(&resp, pos, "request timeout: seq=");
        pos = appendDec(&resp, pos, ping_seq);
    }
    if (console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    ping_count += 1;
    if (ping_count >= ping_total) {
        sendPingSummary();
        ping_state = .idle;
    } else {
        ping_seq += 1;
        if (ping_state == .arp_pending) {
            sendArpRequestOn(ping_iface, ping_target_ip);
            ping_start_ns = now();
        } else {
            sendEchoRequest();
        }
    }
}

// ── TCP checksum helpers ────────────────────────────────────────────────

fn tcpChecksumAdjust(pkt: []u8, transport_start: usize, len: u32, old_ip: [4]u8, new_ip: [4]u8, old_port: u16, new_port: u16) void {
    if (transport_start + 18 > len) return;
    var sum: i32 = @as(i32, @as(u16, pkt[transport_start + 16])) << 8 | pkt[transport_start + 17];
    sum = ~sum & 0xFFFF;

    sum -= @as(i32, @as(u16, old_ip[0])) << 8 | old_ip[1];
    sum -= @as(i32, @as(u16, old_ip[2])) << 8 | old_ip[3];
    sum -= @as(i32, old_port);
    sum += @as(i32, @as(u16, new_ip[0])) << 8 | new_ip[1];
    sum += @as(i32, @as(u16, new_ip[2])) << 8 | new_ip[3];
    sum += @as(i32, new_port);

    while (sum < 0) sum += 0x10000;
    while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum & 0xFFFF;
    if (sum == 0) sum = 0xFFFF;

    pkt[transport_start + 16] = @truncate(@as(u32, @intCast(sum)) >> 8);
    pkt[transport_start + 17] = @truncate(@as(u32, @intCast(sum)));
}

// ── DNS relay ───────────────────────────────────────────────────────────

fn handleDnsFromLan(pkt: []u8, len: u32) void {
    if (!has_wan) return;
    if (len < 34) return;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;
    if (pkt[23] != 17) return;

    const dst_port = readU16Be(pkt[udp_start + 2 ..][0..2]);
    if (dst_port != DNS_PORT) return;

    const src_port = readU16Be(pkt[udp_start..][0..2]);
    var client_ip: [4]u8 = undefined;
    @memcpy(&client_ip, pkt[26..30]);

    const dns_start = udp_start + 8;
    if (dns_start + 2 > len) return;
    const query_id = readU16Be(pkt[dns_start..][0..2]);

    const relay_id = next_dns_id;
    next_dns_id +%= 1;
    if (next_dns_id == 0) next_dns_id = 1;

    var slot: ?*DnsRelay = null;
    var oldest_idx: usize = 0;
    var oldest_ts: u64 = now();
    for (&dns_relays, 0..) |*r, i| {
        if (!r.valid) {
            slot = r;
            break;
        }
        if (r.timestamp_ns < oldest_ts) {
            oldest_ts = r.timestamp_ns;
            oldest_idx = i;
        }
    }
    if (slot == null) slot = &dns_relays[oldest_idx];

    slot.?.* = .{
        .valid = true,
        .client_ip = client_ip,
        .client_port = src_port,
        .query_id = query_id,
        .relay_id = relay_id,
        .timestamp_ns = now(),
    };

    writeU16Be(pkt[dns_start..][0..2], relay_id);

    const gateway_mac = arpLookup(&wan_arp, upstream_dns) orelse {
        sendArpRequestOn(.wan, upstream_dns);
        return;
    };

    @memcpy(pkt[0..6], &gateway_mac);
    @memcpy(pkt[6..12], &wan_mac);
    @memcpy(pkt[26..30], &wan_ip);
    @memcpy(pkt[30..34], &upstream_dns);

    writeU16Be(pkt[udp_start..][0..2], relay_id);

    pkt[udp_start + 6] = 0;
    pkt[udp_start + 7] = 0;

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = computeChecksum(pkt[14..][0..ip_hdr_len]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    wan_stats.tx_packets += 1;
    wan_stats.tx_bytes += len;
    _ = wan_chan.send(pkt[0..len]);
}

fn handleDnsFromWan(pkt: []u8, len: u32) void {
    if (!has_lan) return;
    if (len < 34) return;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;
    if (pkt[23] != 17) return;

    const src_port = readU16Be(pkt[udp_start..][0..2]);
    if (src_port != DNS_PORT) return;

    const dns_start = udp_start + 8;
    if (dns_start + 2 > len) return;
    const resp_id = readU16Be(pkt[dns_start..][0..2]);

    for (&dns_relays) |*r| {
        if (r.valid and r.relay_id == resp_id) {
            writeU16Be(pkt[dns_start..][0..2], r.query_id);

            const client_mac = arpLookup(&lan_arp, r.client_ip) orelse {
                r.valid = false;
                return;
            };

            @memcpy(pkt[0..6], &client_mac);
            @memcpy(pkt[6..12], &lan_mac);
            @memcpy(pkt[26..30], &lan_ip);
            @memcpy(pkt[30..34], &r.client_ip);

            writeU16Be(pkt[udp_start + 2 ..][0..2], r.client_port);
            writeU16Be(pkt[udp_start..][0..2], DNS_PORT);

            pkt[udp_start + 6] = 0;
            pkt[udp_start + 7] = 0;

            pkt[24] = 0;
            pkt[25] = 0;
            const ip_cs = computeChecksum(pkt[14..][0..ip_hdr_len]);
            pkt[24] = @truncate(ip_cs >> 8);
            pkt[25] = @truncate(ip_cs);

            lan_stats.tx_packets += 1;
            lan_stats.tx_bytes += len;
            if (lan_chan) |*ch| {
                _ = ch.send(pkt[0..len]);
            }

            r.valid = false;
            return;
        }
    }
}

// ── Port forwarding (DNAT) ──────────────────────────────────────────────

fn handlePortForward(pkt: []u8, len: u32) bool {
    if (!has_lan) return false;
    if (len < 34) return false;

    const protocol = pkt[23];
    if (protocol != 6 and protocol != 17) return false;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const transport_start = 14 + ip_hdr_len;
    if (transport_start + 4 > len) return false;

    const dst_port = readU16Be(pkt[transport_start + 2 ..][0..2]);
    const proto: Protocol = if (protocol == 6) .tcp else .udp;

    const fwd = portFwdLookup(proto, dst_port) orelse return false;

    const dst_mac = arpLookup(&lan_arp, fwd.lan_ip) orelse {
        sendArpRequestOn(.lan, fwd.lan_ip);
        return true;
    };

    var old_dst_ip: [4]u8 = undefined;
    @memcpy(&old_dst_ip, pkt[30..34]);

    @memcpy(pkt[0..6], &dst_mac);
    @memcpy(pkt[6..12], &lan_mac);
    @memcpy(pkt[30..34], &fwd.lan_ip);
    writeU16Be(pkt[transport_start + 2 ..][0..2], fwd.lan_port);

    if (protocol == 6) {
        tcpChecksumAdjust(pkt, transport_start, len, old_dst_ip, fwd.lan_ip, dst_port, fwd.lan_port);
    } else {
        pkt[transport_start + 6] = 0;
        pkt[transport_start + 7] = 0;
    }

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = computeChecksum(pkt[14..][0..ip_hdr_len]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    lan_stats.tx_packets += 1;
    lan_stats.tx_bytes += len;
    if (lan_chan) |*ch| {
        _ = ch.send(pkt[0..len]);
    }
    return true;
}

// ── NAT routing ─────────────────────────────────────────────────────────

fn natForwardLanToWan(pkt: []u8, len: u32) void {
    if (len < 34) return;

    var dst_ip: [4]u8 = undefined;
    @memcpy(&dst_ip, pkt[30..34]);

    if (eql(&dst_ip, &lan_ip)) return;
    if (isInLanSubnet(dst_ip)) return;

    const gateway_mac = arpLookup(&wan_arp, .{ 10, 0, 2, 1 }) orelse {
        sendArpRequestOn(.wan, .{ 10, 0, 2, 1 });
        return;
    };

    const protocol = pkt[23];
    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;

    if (protocol == 1) {
        const icmp_start = 14 + ip_hdr_len;
        if (icmp_start + 8 > len) return;
        if (pkt[icmp_start] != 8) return;

        const orig_id = readU16Be(pkt[icmp_start + 4 ..][0..2]);
        var src_ip: [4]u8 = undefined;
        @memcpy(&src_ip, pkt[26..30]);

        const nat_entry = natLookupOutbound(.icmp, src_ip, orig_id) orelse
            (natCreateOutbound(.icmp, src_ip, orig_id) orelse return);

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &wan_mac);
        @memcpy(pkt[26..30], &wan_ip);
        writeU16Be(pkt[icmp_start + 4 ..][0..2], nat_entry.wan_port);

        pkt[icmp_start + 2] = 0;
        pkt[icmp_start + 3] = 0;
        const icmp_cs = computeChecksum(pkt[icmp_start..len]);
        pkt[icmp_start + 2] = @truncate(icmp_cs >> 8);
        pkt[icmp_start + 3] = @truncate(icmp_cs);

        pkt[24] = 0;
        pkt[25] = 0;
        const ip_cs = computeChecksum(pkt[14..][0..ip_hdr_len]);
        pkt[24] = @truncate(ip_cs >> 8);
        pkt[25] = @truncate(ip_cs);

        _ = wan_chan.send(pkt[0..len]);
    } else if (protocol == 6 or protocol == 17) {
        const transport_start = 14 + ip_hdr_len;
        if (transport_start + 4 > len) return;

        const orig_port = readU16Be(pkt[transport_start..][0..2]);
        var src_ip: [4]u8 = undefined;
        @memcpy(&src_ip, pkt[26..30]);

        const proto: Protocol = if (protocol == 6) .tcp else .udp;
        const nat_entry = natLookupOutbound(proto, src_ip, orig_port) orelse
            (natCreateOutbound(proto, src_ip, orig_port) orelse return);

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &wan_mac);

        if (protocol == 6) {
            tcpChecksumAdjust(pkt, transport_start, len, src_ip, wan_ip, orig_port, nat_entry.wan_port);
        } else if (transport_start + 8 <= len) {
            pkt[transport_start + 6] = 0;
            pkt[transport_start + 7] = 0;
        }

        @memcpy(pkt[26..30], &wan_ip);
        writeU16Be(pkt[transport_start..][0..2], nat_entry.wan_port);

        pkt[24] = 0;
        pkt[25] = 0;
        const ip_cs = computeChecksum(pkt[14..][0..ip_hdr_len]);
        pkt[24] = @truncate(ip_cs >> 8);
        pkt[25] = @truncate(ip_cs);

        wan_stats.tx_packets += 1;
        wan_stats.tx_bytes += len;
        _ = wan_chan.send(pkt[0..len]);
    }
}

fn natForwardWanToLan(pkt: []u8, len: u32) void {
    if (len < 34) return;

    var dst_ip: [4]u8 = undefined;
    @memcpy(&dst_ip, pkt[30..34]);
    if (!eql(&dst_ip, &wan_ip)) return;

    const protocol = pkt[23];
    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;

    if (protocol == 1) {
        const icmp_start = 14 + ip_hdr_len;
        if (icmp_start + 8 > len) return;
        if (pkt[icmp_start] != 0) return;

        const reply_id = readU16Be(pkt[icmp_start + 4 ..][0..2]);
        const nat_entry = natLookupInbound(.icmp, reply_id) orelse return;

        const dst_mac = arpLookup(&lan_arp, nat_entry.lan_ip) orelse return;

        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &lan_mac);
        @memcpy(pkt[30..34], &nat_entry.lan_ip);
        writeU16Be(pkt[icmp_start + 4 ..][0..2], nat_entry.lan_port);

        pkt[icmp_start + 2] = 0;
        pkt[icmp_start + 3] = 0;
        const icmp_cs = computeChecksum(pkt[icmp_start..len]);
        pkt[icmp_start + 2] = @truncate(icmp_cs >> 8);
        pkt[icmp_start + 3] = @truncate(icmp_cs);

        pkt[24] = 0;
        pkt[25] = 0;
        const ip_cs = computeChecksum(pkt[14..][0..ip_hdr_len]);
        pkt[24] = @truncate(ip_cs >> 8);
        pkt[25] = @truncate(ip_cs);

        if (lan_chan) |*ch| {
            _ = ch.send(pkt[0..len]);
        }
    } else if (protocol == 6 or protocol == 17) {
        const transport_start = 14 + ip_hdr_len;
        if (transport_start + 4 > len) return;

        const dst_port = readU16Be(pkt[transport_start + 2 ..][0..2]);
        const proto: Protocol = if (protocol == 6) .tcp else .udp;
        const nat_entry = natLookupInbound(proto, dst_port) orelse return;

        const dst_mac = arpLookup(&lan_arp, nat_entry.lan_ip) orelse return;

        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &lan_mac);

        var old_dst_ip: [4]u8 = undefined;
        @memcpy(&old_dst_ip, pkt[30..34]);

        if (protocol == 6) {
            tcpChecksumAdjust(pkt, transport_start, len, old_dst_ip, nat_entry.lan_ip, dst_port, nat_entry.lan_port);
        } else if (transport_start + 8 <= len) {
            pkt[transport_start + 6] = 0;
            pkt[transport_start + 7] = 0;
        }

        @memcpy(pkt[30..34], &nat_entry.lan_ip);
        writeU16Be(pkt[transport_start + 2 ..][0..2], nat_entry.lan_port);

        pkt[24] = 0;
        pkt[25] = 0;
        const ip_cs = computeChecksum(pkt[14..][0..ip_hdr_len]);
        pkt[24] = @truncate(ip_cs >> 8);
        pkt[25] = @truncate(ip_cs);

        lan_stats.tx_packets += 1;
        lan_stats.tx_bytes += len;
        if (lan_chan) |*ch| {
            _ = ch.send(pkt[0..len]);
        }
    }
}

// ── Packet dispatch ─────────────────────────────────────────────────────

fn processPacket(iface: Interface, pkt: []u8, len: u32) void {
    if (len < 14) return;

    const stats = ifaceStats(iface);
    stats.rx_packets += 1;
    stats.rx_bytes += len;

    const ethertype = readU16Be(pkt[12..14]);

    if (ethertype == 0x0806) {
        if (len >= 42) {
            var sender_mac: [6]u8 = undefined;
            var sender_ip: [4]u8 = undefined;
            @memcpy(&sender_mac, pkt[22..28]);
            @memcpy(&sender_ip, pkt[28..32]);
            arpLearn(arpTable(iface), sender_ip, sender_mac);

            if (ping_state == .arp_pending and ping_iface == iface) {
                if (arpLookup(arpTable(iface), ping_target_ip)) |mac| {
                    @memcpy(&ping_target_mac, &mac);
                    sendEchoRequest();
                }
            }
        }
        if (handleArp(iface, pkt, len)) |reply| {
            stats.tx_packets += 1;
            stats.tx_bytes += reply.len;
            _ = ifaceChan(iface).send(reply);
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
                    dst_port_fw = readU16Be(pkt[ts_fw + 2 ..][0..2]);
                }
            }
            if (firewallCheck(src_ip_fw, protocol_fw, dst_port_fw) == .block) {
                stats.rx_dropped += 1;
                return;
            }
        }

        var dst_ip: [4]u8 = undefined;
        @memcpy(&dst_ip, pkt[30..34]);

        const my_ip = ifaceIp(iface);
        const is_for_me = eql(&dst_ip, my_ip) or eql(&dst_ip, &lan_broadcast);

        if (is_for_me) {
            if (pkt[23] == 17) {
                const ip_hdr_len_dhcp: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
                const udp_start_dhcp = 14 + ip_hdr_len_dhcp;
                if (udp_start_dhcp + 4 <= len) {
                    const udp_dst = readU16Be(pkt[udp_start_dhcp + 2 ..][0..2]);
                    if (udp_dst == 67 and iface == .lan) {
                        handleDhcpServer(pkt, len);
                        return;
                    }
                    if (udp_dst == DNS_PORT) {
                        if (iface == .lan) {
                            handleDnsFromLan(pkt, len);
                        }
                        return;
                    }
                }
            }
            handleEchoReply(pkt, len);
            if (handleIcmp(iface, pkt, len)) |reply| {
                stats.tx_packets += 1;
                stats.tx_bytes += reply.len;
                _ = ifaceChan(iface).send(reply);
            }
        } else if (iface == .wan and has_lan) {
            if (pkt[23] == 17) {
                const ip_hdr_len_dns: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
                const udp_start_dns = 14 + ip_hdr_len_dns;
                if (udp_start_dns + 4 <= len) {
                    const udp_src_dns = readU16Be(pkt[udp_start_dns..][0..2]);
                    if (udp_src_dns == DNS_PORT) {
                        handleDnsFromWan(pkt, len);
                        return;
                    }
                }
            }
            if (handlePortForward(pkt, len)) return;
            natForwardWanToLan(pkt, len);
        } else if (iface == .lan and has_wan) {
            if (pkt[23] == 17) {
                const ip_hdr_len_dns2: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
                const udp_start_dns2 = 14 + ip_hdr_len_dns2;
                if (udp_start_dns2 + 4 <= len) {
                    const udp_dst_dns = readU16Be(pkt[udp_start_dns2 + 2 ..][0..2]);
                    if (udp_dst_dns == DNS_PORT) {
                        handleDnsFromLan(pkt, len);
                        return;
                    }
                }
            }
            natForwardLanToWan(pkt, len);
        }
    }
}

// ── Console commands ────────────────────────────────────────────────────

fn handleConsoleCommand(data: []const u8) void {
    var chan = &(console_chan orelse return);
    if (eql(data, "status")) {
        var resp: [256]u8 = undefined;
        var pos: usize = 0;
        pos = appendStr(&resp, pos, "WAN: ");
        pos = appendIp(&resp, pos, wan_ip);
        pos = appendStr(&resp, pos, " (");
        pos = appendMac(&resp, pos, wan_mac);
        pos = appendStr(&resp, pos, ")");
        if (has_lan) {
            pos = appendStr(&resp, pos, "\nLAN: ");
            pos = appendIp(&resp, pos, lan_ip);
            pos = appendStr(&resp, pos, " (");
            pos = appendMac(&resp, pos, lan_mac);
            pos = appendStr(&resp, pos, ")");
        }
        _ = chan.send(resp[0..pos]);
    } else if (startsWith(data, "ping ")) {
        if (ping_state != .idle) {
            _ = chan.send("ping: already in progress");
            return;
        }
        if (parseIp(data[5..])) |ip| {
            ping_target_ip = ip;
            ping_seq = 0;
            ping_count = 0;
            ping_received = 0;
            ping_iface = if (isInLanSubnet(ip)) .lan else .wan;

            if (arpLookup(arpTable(ping_iface), ip)) |mac| {
                @memcpy(&ping_target_mac, &mac);
                sendEchoRequest();
            } else {
                ping_state = .arp_pending;
                ping_start_ns = now();
                sendArpRequestOn(ping_iface, ip);
            }
        } else {
            _ = chan.send("ping: invalid IP address");
        }
    } else if (eql(data, "arp")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        var count: u32 = 0;

        pos = appendStr(&resp, pos, "WAN ARP:");
        for (&wan_arp) |*e| {
            if (e.valid) {
                pos = appendStr(&resp, pos, "\n  ");
                pos = appendIp(&resp, pos, e.ip);
                pos = appendStr(&resp, pos, " -> ");
                pos = appendMac(&resp, pos, e.mac);
                count += 1;
            }
        }
        if (has_lan) {
            pos = appendStr(&resp, pos, "\nLAN ARP:");
            for (&lan_arp) |*e| {
                if (e.valid) {
                    pos = appendStr(&resp, pos, "\n  ");
                    pos = appendIp(&resp, pos, e.ip);
                    pos = appendStr(&resp, pos, " -> ");
                    pos = appendMac(&resp, pos, e.mac);
                    count += 1;
                }
            }
        }
        _ = chan.send(resp[0..pos]);
        var summary: [64]u8 = undefined;
        var spos: usize = 0;
        spos = appendStr(&summary, spos, "--- ");
        spos = appendDec(&summary, spos, count);
        spos = appendStr(&summary, spos, " entries ---");
        _ = chan.send(summary[0..spos]);
    } else if (eql(data, "nat")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        var count: u32 = 0;
        for (&nat_table) |*e| {
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
                pos = appendStr(&resp, pos, proto_str);
                pos = appendStr(&resp, pos, " ");
                pos = appendIp(&resp, pos, e.lan_ip);
                pos = appendStr(&resp, pos, ":");
                pos = appendDec(&resp, pos, e.lan_port);
                pos = appendStr(&resp, pos, " -> :");
                pos = appendDec(&resp, pos, e.wan_port);
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
        spos = appendStr(&summary, spos, "--- ");
        spos = appendDec(&summary, spos, count);
        spos = appendStr(&summary, spos, " NAT entries ---");
        _ = chan.send(summary[0..spos]);
    } else if (eql(data, "leases")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        var count: u32 = 0;
        for (&dhcp_leases) |*l| {
            if (l.valid) {
                if (count > 0 and pos < resp.len - 1) {
                    resp[pos] = '\n';
                    pos += 1;
                }
                pos = appendMac(&resp, pos, l.mac);
                pos = appendStr(&resp, pos, " -> ");
                pos = appendIp(&resp, pos, l.ip);
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
        spos = appendStr(&summary, spos, "--- ");
        spos = appendDec(&summary, spos, count);
        spos = appendStr(&summary, spos, " leases ---");
        _ = chan.send(summary[0..spos]);
    } else if (eql(data, "ifstat")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        pos = appendStr(&resp, pos, "WAN: rx=");
        pos = appendDec(&resp, pos, wan_stats.rx_packets);
        pos = appendStr(&resp, pos, " (");
        pos = appendDec(&resp, pos, wan_stats.rx_bytes);
        pos = appendStr(&resp, pos, "B) tx=");
        pos = appendDec(&resp, pos, wan_stats.tx_packets);
        pos = appendStr(&resp, pos, " (");
        pos = appendDec(&resp, pos, wan_stats.tx_bytes);
        pos = appendStr(&resp, pos, "B) drop=");
        pos = appendDec(&resp, pos, wan_stats.rx_dropped);
        if (has_lan) {
            pos = appendStr(&resp, pos, "\nLAN: rx=");
            pos = appendDec(&resp, pos, lan_stats.rx_packets);
            pos = appendStr(&resp, pos, " (");
            pos = appendDec(&resp, pos, lan_stats.rx_bytes);
            pos = appendStr(&resp, pos, "B) tx=");
            pos = appendDec(&resp, pos, lan_stats.tx_packets);
            pos = appendStr(&resp, pos, " (");
            pos = appendDec(&resp, pos, lan_stats.tx_bytes);
            pos = appendStr(&resp, pos, "B) drop=");
            pos = appendDec(&resp, pos, lan_stats.rx_dropped);
        }
        _ = chan.send(resp[0..pos]);
    } else if (startsWith(data, "forward ")) {
        // format: forward <proto> <wan_port> <lan_ip> <lan_port>
        // example: forward tcp 80 192.168.1.100 8080
        const args = data[8..];
        var proto: Protocol = .tcp;
        var rest = args;
        if (startsWith(rest, "tcp ")) {
            proto = .tcp;
            rest = rest[4..];
        } else if (startsWith(rest, "udp ")) {
            proto = .udp;
            rest = rest[4..];
        } else {
            _ = chan.send("forward: usage: forward <tcp|udp> <wan_port> <lan_ip> <lan_port>");
            return;
        }
        if (parsePortIpPort(rest)) |result| {
            if (portFwdAdd(proto, result.port1, result.ip, result.port2)) {
                _ = chan.send("forward: rule added");
            } else {
                _ = chan.send("forward: table full");
            }
        } else {
            _ = chan.send("forward: invalid arguments");
        }
    } else if (startsWith(data, "block ")) {
        if (parseIp(data[6..])) |ip| {
            for (&firewall_rules) |*r| {
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
    } else if (startsWith(data, "allow ")) {
        if (parseIp(data[6..])) |ip| {
            for (&firewall_rules) |*r| {
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
    } else if (eql(data, "rules")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        var count: u32 = 0;

        pos = appendStr(&resp, pos, "Firewall rules:");
        for (&firewall_rules) |*r| {
            if (r.valid) {
                pos = appendStr(&resp, pos, "\n  ");
                pos = appendStr(&resp, pos, if (r.action == .block) "BLOCK " else "ALLOW ");
                pos = appendIp(&resp, pos, r.src_ip);
                if (r.protocol != 0) {
                    pos = appendStr(&resp, pos, " proto=");
                    pos = appendDec(&resp, pos, r.protocol);
                }
                if (r.dst_port != 0) {
                    pos = appendStr(&resp, pos, " port=");
                    pos = appendDec(&resp, pos, r.dst_port);
                }
                count += 1;
            }
        }

        pos = appendStr(&resp, pos, "\nPort forwards:");
        for (&port_forwards) |*f| {
            if (f.valid) {
                pos = appendStr(&resp, pos, "\n  ");
                pos = appendStr(&resp, pos, if (f.protocol == .tcp) "tcp" else "udp");
                pos = appendStr(&resp, pos, " :");
                pos = appendDec(&resp, pos, f.wan_port);
                pos = appendStr(&resp, pos, " -> ");
                pos = appendIp(&resp, pos, f.lan_ip);
                pos = appendStr(&resp, pos, ":");
                pos = appendDec(&resp, pos, f.lan_port);
                count += 1;
            }
        }
        _ = chan.send(resp[0..pos]);
        var summary: [64]u8 = undefined;
        var spos: usize = 0;
        spos = appendStr(&summary, spos, "--- ");
        spos = appendDec(&summary, spos, count);
        spos = appendStr(&summary, spos, " rules ---");
        _ = chan.send(summary[0..spos]);
    } else if (startsWith(data, "dns ")) {
        if (parseIp(data[4..])) |ip| {
            upstream_dns = ip;
            var resp: [64]u8 = undefined;
            var pos: usize = 0;
            pos = appendStr(&resp, pos, "DNS upstream set to ");
            pos = appendIp(&resp, pos, ip);
            _ = chan.send(resp[0..pos]);
        } else {
            _ = chan.send("dns: invalid IP");
        }
    } else {
        _ = chan.send("router: unknown command");
    }
}

fn parsePortIpPort(s: []const u8) ?struct { port1: u16, ip: [4]u8, port2: u16 } {
    var port1: u16 = 0;
    var i: usize = 0;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
        port1 = port1 * 10 + @as(u16, s[i] - '0');
    }
    if (i == 0 or i >= s.len or s[i] != ' ') return null;
    i += 1;

    var ip_end = i;
    while (ip_end < s.len and s[ip_end] != ' ') : (ip_end += 1) {}
    const ip = parseIp(s[i..ip_end]) orelse return null;
    if (ip_end >= s.len) return null;
    i = ip_end + 1;

    var port2: u16 = 0;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
        port2 = port2 * 10 + @as(u16, s[i] - '0');
    }
    if (port2 == 0) return null;
    return .{ .port1 = port1, .ip = ip, .port2 = port2 };
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

    wan_chan = mapShmAsSideB(data_handles[0], data_sizes[0]) orelse {
        syscall.write("router: WAN channel open failed\n");
        return;
    };
    has_wan = true;

    wan_mac = waitForMac(&wan_chan);
    syscall.write("router: WAN MAC learned\n");

    if (has_lan_connection and data_count >= 2) {
        if (mapShmAsSideB(data_handles[1], data_sizes[1])) |ch| {
            lan_chan = ch;
            has_lan = true;
            lan_mac = waitForMac(&(lan_chan.?));
            syscall.write("router: LAN MAC learned\n");
        }
    }

    sendArpRequestOn(.wan, .{ 10, 0, 2, 1 });
    syscall.write("router: sent ARP request on WAN\n");

    while (true) {
        if (console_chan == null) {
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
                            console_chan = channel_mod.Channel.initAsSideA(con_header, @truncate(e.field0));
                            syscall.write("router: console channel connected\n");
                        }
                    }
                    break;
                }
            }
        }

        if (console_chan) |*chan| {
            var cmd_buf: [256]u8 = undefined;
            if (chan.recv(&cmd_buf)) |len| {
                handleConsoleCommand(cmd_buf[0..len]);
            }
        }

        var pkt_buf: [2048]u8 = undefined;
        if (wan_chan.recv(&pkt_buf)) |len| {
            processPacket(.wan, &pkt_buf, len);
        }

        if (lan_chan) |*ch| {
            var lan_pkt: [2048]u8 = undefined;
            if (ch.recv(&lan_pkt)) |len| {
                processPacket(.lan, &lan_pkt, len);
            }
        }

        checkPingTimeout();
        syscall.thread_yield();
    }
}
