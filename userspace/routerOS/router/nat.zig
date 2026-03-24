/// NAT table with lock-free concurrent access.
/// Outbound: keyed by (protocol, lan_ip, lan_port) — LAN thread inserts + looks up.
/// Inbound: keyed by (protocol, wan_port) — WAN thread looks up.
/// Expiry: main thread scans periodically.
///
/// Thread safety: entries use an atomic `state` field. Insert uses CAS on state.
/// Lookup reads state atomically. Expiry writes state atomically.
const arp = @import("arp.zig");
const main = @import("main.zig");
const util = @import("util.zig");

const Interface = main.Interface;

pub const TABLE_SIZE = 256; // power of 2 for hash masking

const ICMP_TIMEOUT_NS: u64 = 60_000_000_000;
const UDP_TIMEOUT_NS: u64 = 120_000_000_000;
const UDP_DNS_TIMEOUT_NS: u64 = 30_000_000_000;
const TCP_ESTABLISHED_TIMEOUT_NS: u64 = 300_000_000_000;
const TCP_OTHER_TIMEOUT_NS: u64 = 30_000_000_000;

const State = enum(u8) {
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
    var h: u32 = @as(u32, protocol) *% 31;
    h +%= @as(u32, lan_ip[0]) *% 257;
    h +%= @as(u32, lan_ip[1]) *% 1031;
    h +%= @as(u32, lan_ip[2]) *% 4099;
    h +%= @as(u32, lan_ip[3]) *% 16411;
    h +%= @as(u32, lan_port) *% 65537;
    return h & (TABLE_SIZE - 1);
}

fn hashInbound(protocol: u8, wan_port: u16) u32 {
    var h: u32 = @as(u32, protocol) *% 31;
    h +%= @as(u32, wan_port) *% 65537;
    return h & (TABLE_SIZE - 1);
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

    var idx = hashOutbound(proto, lan_ip, lan_port);
    var probes: u32 = 0;
    while (probes < TABLE_SIZE) : (probes += 1) {
        const entry = &main.nat_table[idx];
        const s = loadState(entry);
        if (s == .empty or s == .expired) {
            // Try to claim this slot with CAS
            const expected: u8 = @intFromEnum(s);
            if (@cmpxchgWeak(u8, &entry.state, expected, @intFromEnum(State.active), .acq_rel, .monotonic) == null) {
                // Won the slot — fill in fields
                entry.protocol = proto;
                entry.lan_ip = lan_ip;
                entry.lan_port = lan_port;
                entry.wan_port = wan_port;
                entry.dst_ip = dst_ip;
                entry.dst_port = dst_port;
                entry.timestamp_ns = util.now();
                entry.tcp_state = @intFromEnum(TcpState.none);
                if (protocol == .tcp) entry.tcp_state = @intFromEnum(TcpState.syn_sent);
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
    const flags = pkt[transport_start + 13];
    const syn = (flags & 0x02) != 0;
    const fin = (flags & 0x01) != 0;
    const rst = (flags & 0x04) != 0;
    const ack = (flags & 0x10) != 0;

    const current: TcpState = @enumFromInt(entry.tcp_state);
    const new_state: TcpState = switch (current) {
        .none, .syn_sent => if (ack and !syn) .established else .syn_sent,
        .established => if (fin or rst) .fin_wait else .established,
        .fin_wait => if (rst) .none else .fin_wait,
    };
    @atomicStore(u8, &entry.tcp_state, @intFromEnum(new_state), .release);
}

// ── Forwarding (modifies headers in-place, returns true if ready) ───────

/// Rewrite headers in-place for LAN→WAN NAT. Returns true if ready to forward.
pub fn forwardLanToWan(pkt: []u8, len: u32) bool {
    if (len < 34) return false;

    var dst_ip: [4]u8 = undefined;
    @memcpy(&dst_ip, pkt[30..34]);

    if (util.eql(&dst_ip, &main.lan_iface.ip)) return false;
    if (main.isInLanSubnet(dst_ip)) return false;

    const gateway_mac = arp.lookup(&main.wan_iface.arp_table, .{ 10, 0, 2, 1 }) orelse {
        arp.sendRequest(.wan, .{ 10, 0, 2, 1 });
        return false;
    };

    const protocol = pkt[23];
    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;

    if (protocol == 1) {
        const icmp_start = 14 + ip_hdr_len;
        if (icmp_start + 8 > len) return false;
        if (pkt[icmp_start] != 8) return false;

        const orig_id = util.readU16Be(pkt[icmp_start + 4 ..][0..2]);
        var src_ip: [4]u8 = undefined;
        @memcpy(&src_ip, pkt[26..30]);
        var dst_ip_nat: [4]u8 = undefined;
        @memcpy(&dst_ip_nat, pkt[30..34]);

        const nat_entry = lookupOutbound(.icmp, src_ip, orig_id) orelse
            (createOutbound(.icmp, src_ip, orig_id, dst_ip_nat, 0) orelse return false);

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &main.wan_iface.mac);
        @memcpy(pkt[26..30], &main.wan_iface.ip);
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
        return true;
    } else if (protocol == 6 or protocol == 17) {
        const transport_start = 14 + ip_hdr_len;
        if (transport_start + 4 > len) return false;

        const orig_port = util.readU16Be(pkt[transport_start..][0..2]);
        var src_ip: [4]u8 = undefined;
        @memcpy(&src_ip, pkt[26..30]);
        var dst_ip_tcp: [4]u8 = undefined;
        @memcpy(&dst_ip_tcp, pkt[30..34]);
        const dst_port_tcp = util.readU16Be(pkt[transport_start + 2 ..][0..2]);
        const proto: util.Protocol = if (protocol == 6) .tcp else .udp;
        const nat_entry = lookupOutbound(proto, src_ip, orig_port) orelse
            (createOutbound(proto, src_ip, orig_port, dst_ip_tcp, dst_port_tcp) orelse return false);

        if (protocol == 6) updateTcpState(nat_entry, pkt, len, transport_start);

        @memcpy(pkt[0..6], &gateway_mac);
        @memcpy(pkt[6..12], &main.wan_iface.mac);

        if (protocol == 6) {
            util.tcpChecksumAdjust(pkt, transport_start, len, src_ip, main.wan_iface.ip, orig_port, nat_entry.wan_port);
        } else if (transport_start + 8 <= len) {
            pkt[transport_start + 6] = 0;
            pkt[transport_start + 7] = 0;
        }

        @memcpy(pkt[26..30], &main.wan_iface.ip);
        util.writeU16Be(pkt[transport_start..][0..2], nat_entry.wan_port);

        pkt[24] = 0;
        pkt[25] = 0;
        const ip_cs = util.computeChecksum(pkt[14..][0..ip_hdr_len]);
        pkt[24] = @truncate(ip_cs >> 8);
        pkt[25] = @truncate(ip_cs);
        return true;
    }
    return false;
}

/// Rewrite headers in-place for WAN→LAN NAT reverse. Returns true if ready to forward.
pub fn forwardWanToLan(pkt: []u8, len: u32) bool {
    if (len < 34) return false;

    var dst_ip: [4]u8 = undefined;
    @memcpy(&dst_ip, pkt[30..34]);
    if (!util.eql(&dst_ip, &main.wan_iface.ip)) return false;

    const protocol = pkt[23];
    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;

    if (protocol == 1) {
        const icmp_start = 14 + ip_hdr_len;
        if (icmp_start + 8 > len) return false;
        if (pkt[icmp_start] != 0) return false;

        const reply_id = util.readU16Be(pkt[icmp_start + 4 ..][0..2]);
        const nat_entry = lookupInbound(.icmp, reply_id) orelse return false;
        const dst_mac = arp.lookup(&main.lan_iface.arp_table, nat_entry.lan_ip) orelse return false;

        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &main.lan_iface.mac);
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
        return true;
    } else if (protocol == 6 or protocol == 17) {
        const transport_start = 14 + ip_hdr_len;
        if (transport_start + 4 > len) return false;

        const dst_port = util.readU16Be(pkt[transport_start + 2 ..][0..2]);
        const proto: util.Protocol = if (protocol == 6) .tcp else .udp;
        const nat_entry = lookupInbound(proto, dst_port) orelse return false;

        if (protocol == 6) updateTcpState(nat_entry, pkt, len, transport_start);

        const dst_mac = arp.lookup(&main.lan_iface.arp_table, nat_entry.lan_ip) orelse return false;

        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &main.lan_iface.mac);

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
        return true;
    }
    return false;
}
