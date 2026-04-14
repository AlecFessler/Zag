const std = @import("std");
const router = @import("router");

const arp = router.protocols.arp;
const dhcp_server = router.protocols.dhcp_server;
const dns = router.protocols.dns;
const firewall = router.protocols.ipv4.firewall;
const firewall6 = router.protocols.ipv6.firewall;
const frag = router.protocols.frag;
const log = router.log;
const nat = router.protocols.ipv4.nat;
const state = router.state;
const util = router.util;

pub const InvariantError = error{
    NatDuplicateOutboundKey,
    NatDuplicateInboundKey,
    NatInvalidProtocol,
    NatInvalidTcpState,
    NatInvalidWanPort,
    ArpDuplicateIp,
    ArpZeroMac,
    PortForwardDuplicateWanPort,
    NatPortCounterCorrupted,
    InterfaceIpCorrupted,
    DnsDuplicateRelayId,
    DnsInvalidRelayEntry,
    DnsCacheDuplicateQuestion,
    DnsCacheInvalidEntry,
    DhcpDuplicateMac,
    DhcpDuplicateIp,
    DhcpInvalidIp,
    DhcpNextIpCorrupted,
    StaticLeaseDuplicateMac,
    StaticLeaseDuplicateIp,
    StaticLeaseInvalidIp,
    StaticDynamicIpConflict,
    FragDuplicateEntry,
    Ipv6DuplicateConn,
    Ipv6InvalidProtocol,
    LogRingCorrupted,
    PortForwardInvalidLeaseSource,
};

pub fn validateAll() InvariantError!void {
    try validateNatTable();
    try validateArpTable(&state.wan_iface.arp_table, "wan");
    try validateArpTable(&state.lan_iface.arp_table, "lan");
    try validateFirewallState();
    try validateDnsRelayTable();
    try validateDnsCacheTable();
    try validateDhcpLeases();
    try validateStaticLeases();
    try validateFragTable();
    try validateIpv6ConnTable();
    try validateGeneralState();
    try validateLogRing();
}

fn validateNatTable() InvariantError!void {
    for (&state.nat_table, 0..) |*entry, i| {
        const entry_state = @atomicLoad(u8, &entry.state, .acquire);
        if (entry_state != @intFromEnum(nat.State.active)) continue;

        // Valid protocol
        if (entry.protocol != 1 and entry.protocol != 6 and entry.protocol != 17) {
            std.debug.print("NAT: entry {} invalid protocol {}\n", .{ i, entry.protocol });
            return InvariantError.NatInvalidProtocol;
        }

        // Valid TCP state
        if (entry.protocol == 6 and entry.tcp_state > 3) {
            std.debug.print("NAT: entry {} invalid tcp_state {}\n", .{ i, entry.tcp_state });
            return InvariantError.NatInvalidTcpState;
        }

        // WAN port in valid range
        if (entry.wan_port < 10000) {
            std.debug.print("NAT: entry {} wan_port {} < 10000\n", .{ i, entry.wan_port });
            return InvariantError.NatInvalidWanPort;
        }

        // No duplicate keys
        for (state.nat_table[i + 1 ..], i + 1..) |*other, j| {
            const other_state = @atomicLoad(u8, &other.state, .acquire);
            if (other_state != @intFromEnum(nat.State.active)) continue;

            if (entry.protocol == other.protocol and
                std.mem.eql(u8, &entry.lan_ip, &other.lan_ip) and
                entry.lan_port == other.lan_port)
            {
                std.debug.print("NAT: duplicate outbound key at {} and {}\n", .{ i, j });
                return InvariantError.NatDuplicateOutboundKey;
            }

            if (entry.protocol == other.protocol and entry.wan_port == other.wan_port) {
                std.debug.print("NAT: duplicate inbound key at {} and {}\n", .{ i, j });
                return InvariantError.NatDuplicateInboundKey;
            }
        }
    }
}

fn validateArpTable(table: *const [arp.TABLE_SIZE]arp.ArpEntry, name: []const u8) InvariantError!void {
    for (table, 0..) |*entry, i| {
        if (!entry.valid) continue;

        if (std.mem.eql(u8, &entry.mac, &[6]u8{ 0, 0, 0, 0, 0, 0 })) {
            std.debug.print("ARP ({s}): entry {} zero MAC\n", .{ name, i });
            return InvariantError.ArpZeroMac;
        }

        for (table[i + 1 ..], i + 1..) |*other, j| {
            if (!other.valid) continue;
            if (std.mem.eql(u8, &entry.ip, &other.ip)) {
                std.debug.print("ARP ({s}): duplicate IP at {} and {}\n", .{ name, i, j });
                return InvariantError.ArpDuplicateIp;
            }
        }
    }
}

fn validateFirewallState() InvariantError!void {
    for (state.port_forwards, 0..) |fwd, i| {
        if (!fwd.valid) continue;

        // Lease/source consistency: manual entries must have no lease, leased entries must have non-manual source
        if (fwd.source == .manual and fwd.lease_expiry_ns != 0) {
            std.debug.print("FW: port forward {} has manual source but non-zero lease\n", .{i});
            return InvariantError.PortForwardInvalidLeaseSource;
        }

        for (state.port_forwards[i + 1 ..], i + 1..) |other, j| {
            if (!other.valid) continue;
            if (fwd.protocol == other.protocol and fwd.wan_port == other.wan_port) {
                std.debug.print("FW: duplicate port forward at {} and {}\n", .{ i, j });
                return InvariantError.PortForwardDuplicateWanPort;
            }
        }
    }
}

fn validateDnsRelayTable() InvariantError!void {
    for (&state.dns_relays, 0..) |*r, i| {
        if (!r.valid) continue;

        // Valid relay entries should have non-zero relay_id and client_port
        if (r.relay_id == 0) {
            std.debug.print("DNS: entry {} has relay_id 0\n", .{i});
            return InvariantError.DnsInvalidRelayEntry;
        }
        // Note: client_port 0 is technically valid (mutated packets can send from port 0)

        // No duplicate relay_ids
        for (state.dns_relays[i + 1 ..], i + 1..) |*other, j| {
            if (!other.valid) continue;
            if (r.relay_id == other.relay_id) {
                std.debug.print("DNS: duplicate relay_id at {} and {}\n", .{ i, j });
                return InvariantError.DnsDuplicateRelayId;
            }
        }
    }
}

fn validateDnsCacheTable() InvariantError!void {
    for (&state.dns_cache, 0..) |*entry, i| {
        if (!entry.valid) continue;

        if (entry.question_len == 0 or entry.question_len > dns.MAX_QUESTION_LEN) {
            std.debug.print("DNS_CACHE: entry {} invalid question_len {}\n", .{ i, entry.question_len });
            return InvariantError.DnsCacheInvalidEntry;
        }

        if (entry.dns_payload_len < 12 or entry.dns_payload_len > dns.MAX_DNS_PAYLOAD) {
            std.debug.print("DNS_CACHE: entry {} invalid payload_len {}\n", .{ i, entry.dns_payload_len });
            return InvariantError.DnsCacheInvalidEntry;
        }

        if (entry.min_ttl_secs == 0) {
            std.debug.print("DNS_CACHE: entry {} has zero TTL\n", .{i});
            return InvariantError.DnsCacheInvalidEntry;
        }

        for (state.dns_cache[i + 1 ..], i + 1..) |*other, j| {
            if (!other.valid) continue;
            if (entry.question_len == other.question_len and
                std.mem.eql(u8, entry.question[0..entry.question_len], other.question[0..other.question_len]))
            {
                std.debug.print("DNS_CACHE: duplicate question at {} and {}\n", .{ i, j });
                return InvariantError.DnsCacheDuplicateQuestion;
            }
        }
    }
}

fn validateDhcpLeases() InvariantError!void {
    for (&state.dhcp_leases, 0..) |*l, i| {
        if (!l.valid) continue;

        // IP must be in 10.1.1.100-255 range
        if (l.ip[0] != 10 or l.ip[1] != 1 or l.ip[2] != 1 or l.ip[3] < 100) {
            std.debug.print("DHCP: lease {} has invalid IP {}.{}.{}.{}\n", .{
                i, l.ip[0], l.ip[1], l.ip[2], l.ip[3],
            });
            return InvariantError.DhcpInvalidIp;
        }

        // No duplicate MACs or IPs
        for (state.dhcp_leases[i + 1 ..], i + 1..) |*other, j| {
            if (!other.valid) continue;
            if (std.mem.eql(u8, &l.mac, &other.mac)) {
                std.debug.print("DHCP: duplicate MAC at {} and {}\n", .{ i, j });
                return InvariantError.DhcpDuplicateMac;
            }
            if (std.mem.eql(u8, &l.ip, &other.ip)) {
                std.debug.print("DHCP: duplicate IP at {} and {}\n", .{ i, j });
                return InvariantError.DhcpDuplicateIp;
            }
        }
    }

    // dhcp_next_ip must be >= 100
    if (state.dhcp_next_ip < 100) {
        std.debug.print("DHCP: dhcp_next_ip {} < 100\n", .{state.dhcp_next_ip});
        return InvariantError.DhcpNextIpCorrupted;
    }
}

fn validateStaticLeases() InvariantError!void {
    for (&state.dhcp_static_leases, 0..) |*s, i| {
        if (s.state == 0) continue;

        // IP must be in 10.1.1.2-255 range
        if (s.ip[0] != 10 or s.ip[1] != 1 or s.ip[2] != 1 or s.ip[3] < 2) {
            std.debug.print("STATIC_DHCP: lease {} has invalid IP {}.{}.{}.{}\n", .{
                i, s.ip[0], s.ip[1], s.ip[2], s.ip[3],
            });
            return InvariantError.StaticLeaseInvalidIp;
        }

        // No duplicate MACs or IPs within static table
        for (state.dhcp_static_leases[i + 1 ..], i + 1..) |*other, j| {
            if (other.state == 0) continue;
            if (std.mem.eql(u8, &s.mac, &other.mac)) {
                std.debug.print("STATIC_DHCP: duplicate MAC at {} and {}\n", .{ i, j });
                return InvariantError.StaticLeaseDuplicateMac;
            }
            if (std.mem.eql(u8, &s.ip, &other.ip)) {
                std.debug.print("STATIC_DHCP: duplicate IP at {} and {}\n", .{ i, j });
                return InvariantError.StaticLeaseDuplicateIp;
            }
        }

        // No IP conflict with dynamic leases (different MAC, same IP)
        for (&state.dhcp_leases) |*l| {
            if (!l.valid) continue;
            if (std.mem.eql(u8, &s.ip, &l.ip) and !std.mem.eql(u8, &s.mac, &l.mac)) {
                std.debug.print("STATIC_DHCP: static/dynamic IP conflict at static {} vs dynamic\n", .{i});
                return InvariantError.StaticDynamicIpConflict;
            }
        }
    }
}

fn validateFragTable() InvariantError!void {
    for (&state.frag_table, 0..) |*f, i| {
        if (!f.valid) continue;
        for (state.frag_table[i + 1 ..], i + 1..) |*other, j| {
            if (!other.valid) continue;
            if (f.ip_id == other.ip_id and std.mem.eql(u8, &f.src_ip, &other.src_ip)) {
                std.debug.print("FRAG: duplicate entry at {} and {}\n", .{ i, j });
                return InvariantError.FragDuplicateEntry;
            }
        }
    }
}

fn validateIpv6ConnTable() InvariantError!void {
    for (&state.conn6_table, 0..) |*e, i| {
        const st = @atomicLoad(u8, &e.state, .acquire);
        if (st != @intFromEnum(firewall6.ConnState.active)) continue;

        // Valid protocol
        if (e.protocol != 6 and e.protocol != 17) {
            std.debug.print("IPv6: entry {} invalid protocol {}\n", .{ i, e.protocol });
            return InvariantError.Ipv6InvalidProtocol;
        }
    }
}

fn validateGeneralState() InvariantError!void {
    if (state.next_nat_port < 10000) {
        std.debug.print("General: next_nat_port {} < 10000\n", .{state.next_nat_port});
        return InvariantError.NatPortCounterCorrupted;
    }

    if (!std.mem.eql(u8, &state.wan_iface.ip, &[4]u8{ 10, 0, 2, 15 })) {
        return InvariantError.InterfaceIpCorrupted;
    }

    if (!std.mem.eql(u8, &state.lan_iface.ip, &[4]u8{ 10, 1, 1, 1 })) {
        return InvariantError.InterfaceIpCorrupted;
    }
}

fn validateLogRing() InvariantError!void {
    const wp = log.getWritePos();
    const rp = log.getReadPos();

    // write_pos must be >= read_pos (modular)
    if (wp -% rp > log.getRingSize()) {
        std.debug.print("LOG: ring corrupt write_pos={} read_pos={}\n", .{ wp, rp });
        return InvariantError.LogRingCorrupted;
    }

    // Check that all published entries have valid msg_id and level values
    var idx = rp;
    while (idx < wp) : (idx += 1) {
        const seq = log.getEntrySequence(idx);
        if (seq == idx + 1) {
            // Published entry -- validate level (looked up from msg table)
            const level = log.getEntryLevel(idx);
            if (level > @intFromEnum(log.Level.debug)) {
                std.debug.print("LOG: entry {} invalid level {}\n", .{ idx, level });
                return InvariantError.LogRingCorrupted;
            }
        }
    }
}
