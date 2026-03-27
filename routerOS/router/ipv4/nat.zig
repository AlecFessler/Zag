/// NAT table with lock-free concurrent access.
/// Outbound: keyed by (protocol, lan_ip, lan_port) — LAN thread inserts + looks up.
/// Inbound: keyed by (protocol, wan_port) — WAN thread looks up.
/// Expiry: main thread scans periodically.
///
/// Thread safety: entries use an atomic `state` field. Insert uses CAS on state.
/// Lookup reads state atomically. Expiry writes state atomically.
const router = @import("router");

const arp = router.net.arp;
const h = router.net.headers;
const main = router.state;
const util = router.util;

const assert = util.assert;

const Interface = main.Interface;

pub const TABLE_SIZE = 4096; // power of 2 for hash masking

const ICMP_TIMEOUT_NS: u64 = 60_000_000_000;
const UDP_TIMEOUT_NS: u64 = 120_000_000_000;
const UDP_DNS_TIMEOUT_NS: u64 = 30_000_000_000;
const TCP_ESTABLISHED_TIMEOUT_NS: u64 = 300_000_000_000;
const TCP_OTHER_TIMEOUT_NS: u64 = 30_000_000_000;

pub const State = enum(u8) {
    empty = 0,
    active = 1,
    expired = 2, // tombstone for linear probing
};

const TcpState = enum(u8) {
    none = 0,
    syn_sent = 1,
    established = 2,
    fin_wait = 3,
};

pub const NatEntry = struct {
    // Atomic state field — all reads/writes go through atomics
    state: u8 align(8) = @intFromEnum(State.empty),

    protocol: u8 = 0,
    lan_port: u16 = 0,
    wan_port: u16 = 0,
    dst_port: u16 = 0,
    lan_ip: [4]u8 = .{ 0, 0, 0, 0 },
    dst_ip: [4]u8 = .{ 0, 0, 0, 0 },
    timestamp_ns: u64 = 0,
    tcp_state: u8 = 0,
};

pub const empty = NatEntry{};

// ── Hash functions ──────────────────────────────────────────────────────

fn hashOutbound(protocol: u8, lan_ip: [4]u8, lan_port: u16) u32 {
    var hash: u32 = @as(u32, protocol) *% 31;
    hash +%= @as(u32, lan_ip[0]) *% 257;
    hash +%= @as(u32, lan_ip[1]) *% 1031;
    hash +%= @as(u32, lan_ip[2]) *% 4099;
    hash +%= @as(u32, lan_ip[3]) *% 16411;
    hash +%= @as(u32, lan_port) *% 65537;
    return hash & (TABLE_SIZE - 1);
}

fn hashInbound(protocol: u8, wan_port: u16) u32 {
    var hash: u32 = @as(u32, protocol) *% 31;
    hash +%= @as(u32, wan_port) *% 65537;
    return hash & (TABLE_SIZE - 1);
}

fn loadState(entry: *const NatEntry) State {
    return @enumFromInt(@atomicLoad(u8, &entry.state, .acquire));
}

fn storeState(entry: *NatEntry, s: State) void {
    @atomicStore(u8, &entry.state, @intFromEnum(s), .release);
}

// ── Lookup ──────────────────────────────────────────────────────────────

fn lookupOutbound(protocol: util.Protocol, lan_ip: [4]u8, lan_port: u16) ?*NatEntry {
    const proto: u8 = @intFromEnum(protocol);
    var idx = hashOutbound(proto, lan_ip, lan_port);
    var probes: u32 = 0;
    while (probes < TABLE_SIZE) : (probes += 1) {
        const entry = &main.nat_table[idx];
        const s = loadState(entry);
        if (s == .empty) return null; // empty slot = end of chain
        if (s == .active and entry.protocol == proto and
            util.eql(&entry.lan_ip, &lan_ip) and entry.lan_port == lan_port)
        {
            @atomicStore(u64, &entry.timestamp_ns, util.now(), .release);
            return entry;
        }
        idx = (idx + 1) & (TABLE_SIZE - 1);
    }
    return null;
}

fn lookupInbound(protocol: util.Protocol, wan_port: u16) ?*NatEntry {
    const proto: u8 = @intFromEnum(protocol);
    // Linear scan — inbound doesn't have its own hash table, scan all
    for (&main.nat_table) |*entry| {
        if (loadState(entry) == .active and entry.protocol == proto and entry.wan_port == wan_port) {
            @atomicStore(u64, &entry.timestamp_ns, util.now(), .release);
            return entry;
        }
    }
    return null;
}

fn createOutbound(protocol: util.Protocol, lan_ip: [4]u8, lan_port: u16, dst_ip: [4]u8, dst_port: u16) ?*NatEntry {
    const proto: u8 = @intFromEnum(protocol);
    const wan_port = @atomicRmw(u16, &main.next_nat_port, .Add, 1, .monotonic);
    // Prevent wraparound into privileged/low port range
    if (main.next_nat_port < 10000) main.next_nat_port = 10000;

    var idx = hashOutbound(proto, lan_ip, lan_port);
    var probes: u32 = 0;
    while (probes < TABLE_SIZE) : (probes += 1) {
        const entry = &main.nat_table[idx];
        const s = loadState(entry);
        if (s == .empty or s == .expired) {
            // Write data fields first — safe because readers check
            // state == .active (via acquire) before reading data, and
            // we haven't published .active yet.
            entry.protocol = proto;
            entry.lan_ip = lan_ip;
            entry.lan_port = lan_port;
            entry.wan_port = wan_port;
            entry.dst_ip = dst_ip;
            entry.dst_port = dst_port;
            entry.timestamp_ns = util.now();
            entry.tcp_state = @intFromEnum(TcpState.none);
            if (protocol == .tcp) entry.tcp_state = @intFromEnum(TcpState.syn_sent);
            // Publish: CAS .acq_rel acts as release fence for the above stores.
            // Readers' acquire load on state pairs with this.
            const expected: u8 = @intFromEnum(s);
            if (@cmpxchgWeak(u8, &entry.state, expected, @intFromEnum(State.active), .acq_rel, .monotonic) == null) {
                // Post-condition: entry is reachable via lookup
                if (lookupOutbound(protocol, lan_ip, lan_port) == null) {
                    const dbg_idx = hashOutbound(proto, lan_ip, lan_port);
                    router.log.write(.nat_postcondition_fail);
                    _ = dbg_idx;
                    assert(false);
                }
                return entry;
            }
            // CAS failed — another thread claimed it, continue probing
        }
        idx = (idx + 1) & (TABLE_SIZE - 1);
    }
    return null;
}

// ── Expiry (main thread only) ───────────────────────────────────────────

pub fn expire() void {
    const now_ns = util.now();
    for (&main.nat_table) |*entry| {
        if (loadState(entry) != .active) continue;
        // Invariant: active entries must have valid protocol (set by createOutbound)
        assert(entry.protocol == 1 or entry.protocol == 6 or entry.protocol == 17);
        const timeout = switch (@as(util.Protocol, @enumFromInt(entry.protocol))) {
            .icmp => ICMP_TIMEOUT_NS,
            .udp => if (entry.dst_port == 53) UDP_DNS_TIMEOUT_NS else UDP_TIMEOUT_NS,
            .tcp => if (entry.tcp_state == @intFromEnum(TcpState.established)) TCP_ESTABLISHED_TIMEOUT_NS else TCP_OTHER_TIMEOUT_NS,
        };
        const ts = @atomicLoad(u64, &entry.timestamp_ns, .acquire);
        if (now_ns -| ts > timeout) {
            storeState(entry, .expired);
        }
    }
}

// ── TCP state tracking ──────────────────────────────────────────────────

fn updateTcpState(entry: *NatEntry, pkt: []const u8, len: u32, transport_start: usize) void {
    if (transport_start + 14 > len) return;
    const tcp = h.TcpHeader.parse(pkt[transport_start..]) orelse return;
    const syn = tcp.isSyn();
    const fin = tcp.isFin();
    const rst = tcp.isRst();
    const ack_ = tcp.isAck();

    const current: TcpState = @enumFromInt(entry.tcp_state);
    const new_state: TcpState = switch (current) {
        .none, .syn_sent => if (ack_ and !syn) .established else .syn_sent,
        .established => if (fin or rst) .fin_wait else .established,
        .fin_wait => if (rst) .none else .fin_wait,
    };
    // Post-condition: state transitions are valid (no backward jumps except RST→none)
    const valid_transition = switch (current) {
        .none, .syn_sent => new_state == .syn_sent or new_state == .established,
        .established => new_state == .established or new_state == .fin_wait,
        .fin_wait => new_state == .fin_wait or new_state == .none,
    };
    assert(valid_transition);
    @atomicStore(u8, &entry.tcp_state, @intFromEnum(new_state), .release);
}

// ── Forwarding (modifies headers in-place, returns true if ready) ───────

/// Rewrite headers in-place for LAN→WAN NAT. Returns true if ready to forward.
pub fn forwardLanToWan(pkt: []u8, len: u32) bool {
    if (len < 34) return false;

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return false;

    if (util.eql(&ip.dst_ip, &main.lan_iface.ip)) return false;
    if (main.isInLanSubnet(ip.dst_ip)) return false;

    const gateway_mac = arp.lookup(&main.wan_iface.arp_table, main.wan_gateway) orelse {
        arp.sendRequest(.wan, main.wan_gateway);
        return false;
    };

    const protocol = ip.protocol;
    const ip_hdr_len = ip.headerLen();

    if (protocol == h.Ipv4Header.PROTO_ICMP) {
        const icmp_start = 14 + ip_hdr_len;
        if (icmp_start + 8 > len) return false;
        const icmp = h.IcmpHeader.parseMut(pkt[icmp_start..]) orelse return false;
        if (icmp.icmp_type != h.IcmpHeader.TYPE_ECHO_REQUEST) return false;

        const orig_id = icmp.id();
        const src_ip = ip.src_ip;
        const dst_ip_nat = ip.dst_ip;

        const nat_entry = lookupOutbound(.icmp, src_ip, orig_id) orelse
            (createOutbound(.icmp, src_ip, orig_id, dst_ip_nat, 0) orelse return false);

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &main.wan_iface.mac);
        @memcpy(&ip.src_ip, &main.wan_iface.ip);
        icmp.setId(nat_entry.wan_port);

        icmp.computeAndSetChecksum(pkt[icmp_start..len]);
        ip.computeAndSetChecksum(pkt);
        return true;
    } else if (protocol == h.Ipv4Header.PROTO_TCP or protocol == h.Ipv4Header.PROTO_UDP) {
        const transport_start = 14 + ip_hdr_len;
        if (transport_start + 4 > len) return false;

        const tcp = h.TcpHeader.parseMut(pkt[transport_start..]) orelse return false;
        const orig_port = tcp.srcPort();
        const src_ip = ip.src_ip;
        const dst_ip_tcp = ip.dst_ip;
        const dst_port_tcp = tcp.dstPort();
        const proto: util.Protocol = if (protocol == h.Ipv4Header.PROTO_TCP) .tcp else .udp;
        const nat_entry = lookupOutbound(proto, src_ip, orig_port) orelse
            (createOutbound(proto, src_ip, orig_port, dst_ip_tcp, dst_port_tcp) orelse return false);

        if (protocol == h.Ipv4Header.PROTO_TCP) updateTcpState(nat_entry, pkt, len, transport_start);

        // Rewrite Ethernet header
        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &main.wan_iface.mac);

        // Rewrite IP source and transport source port
        @memcpy(&ip.src_ip, &main.wan_iface.ip);
        tcp.setSrcPort(nat_entry.wan_port);

        // Recompute checksums after all fields are written
        ip.computeAndSetChecksum(pkt);

        util.recomputeTransportChecksum(pkt, transport_start, len, protocol);
        // Post-conditions: NAT rewrite produced valid results
        // Only check when IHL is valid (malformed IHL can cause overlapping writes)
        if (ip_hdr_len >= 20) {
            assert(util.eql(&ip.src_ip, &main.wan_iface.ip));
            assert(util.eql(pkt[6..12], &main.wan_iface.mac));
            if (14 + ip_hdr_len <= pkt.len) {
                assert(util.verifyIpChecksum(pkt[14 .. 14 + ip_hdr_len]));
            }
        }
        return true;
    }
    return false;
}

/// Rewrite headers in-place for WAN→LAN NAT reverse. Returns true if ready to forward.
pub fn forwardWanToLan(pkt: []u8, len: u32) bool {
    if (len < 34) return false;

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return false;
    if (!util.eql(&ip.dst_ip, &main.wan_iface.ip)) return false;

    const protocol = ip.protocol;
    const ip_hdr_len = ip.headerLen();

    if (protocol == h.Ipv4Header.PROTO_ICMP) {
        const icmp_start = 14 + ip_hdr_len;
        if (icmp_start + 8 > len) return false;
        const icmp = h.IcmpHeader.parseMut(pkt[icmp_start..]) orelse return false;
        if (icmp.icmp_type != h.IcmpHeader.TYPE_ECHO_REPLY) return false;

        const reply_id = icmp.id();
        const nat_entry = lookupInbound(.icmp, reply_id) orelse return false;
        const dst_mac = arp.lookup(&main.lan_iface.arp_table, nat_entry.lan_ip) orelse return false;

        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &main.lan_iface.mac);
        @memcpy(&ip.dst_ip, &nat_entry.lan_ip);
        icmp.setId(nat_entry.lan_port);

        icmp.computeAndSetChecksum(pkt[icmp_start..len]);
        ip.computeAndSetChecksum(pkt);
        return true;
    } else if (protocol == h.Ipv4Header.PROTO_TCP or protocol == h.Ipv4Header.PROTO_UDP) {
        const transport_start = 14 + ip_hdr_len;
        if (transport_start + 4 > len) return false;

        const tcp = h.TcpHeader.parseMut(pkt[transport_start..]) orelse return false;
        const dst_port = tcp.dstPort();
        const proto: util.Protocol = if (protocol == h.Ipv4Header.PROTO_TCP) .tcp else .udp;
        const nat_entry = lookupInbound(proto, dst_port) orelse return false;

        if (protocol == h.Ipv4Header.PROTO_TCP) updateTcpState(nat_entry, pkt, len, transport_start);

        const dst_mac = arp.lookup(&main.lan_iface.arp_table, nat_entry.lan_ip) orelse {
            arp.sendRequest(.lan, nat_entry.lan_ip);
            return false;
        };

        // Rewrite Ethernet header
        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &main.lan_iface.mac);

        // Rewrite IP dest and transport dest port
        @memcpy(&ip.dst_ip, &nat_entry.lan_ip);
        tcp.setDstPort(nat_entry.lan_port);

        // Recompute checksums after all fields are written
        ip.computeAndSetChecksum(pkt);

        util.recomputeTransportChecksum(pkt, transport_start, len, protocol);
        // Post-conditions: reverse NAT rewrite produced valid results
        if (ip_hdr_len >= 20) {
            assert(util.eql(&ip.dst_ip, &nat_entry.lan_ip));
            assert(util.eql(pkt[6..12], &main.lan_iface.mac));
            if (14 + ip_hdr_len <= pkt.len) {
                assert(util.verifyIpChecksum(pkt[14 .. 14 + ip_hdr_len]));
            }
        }
        return true;
    }
    return false;
}
