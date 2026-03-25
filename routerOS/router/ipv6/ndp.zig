const router = @import("router");

const main = router.state;
const util = router.util;

const Interface = main.Interface;

pub const TABLE_SIZE = 32;
const EXPIRY_NS: u64 = 300_000_000_000; // 5 minutes

pub const NdpEntry = struct {
    ip6: [16]u8,
    mac: [6]u8,
    valid: bool,
    is_router: bool,
    timestamp_ns: u64,
};

pub const empty = NdpEntry{
    .ip6 = .{0} ** 16,
    .mac = .{0} ** 6,
    .valid = false,
    .is_router = false,
    .timestamp_ns = 0,
};

pub fn lookup(table: *const [TABLE_SIZE]NdpEntry, ip6: [16]u8) ?[6]u8 {
    for (table) |*e| {
        if (e.valid and util.eql(&e.ip6, &ip6)) return e.mac;
    }
    return null;
}

pub fn learn(table: *[TABLE_SIZE]NdpEntry, ip6: [16]u8, mac: [6]u8, is_router: bool) void {
    const now_ns = util.now();
    // Update existing
    for (table) |*e| {
        if (e.valid and util.eql(&e.ip6, &ip6)) {
            @memcpy(&e.mac, &mac);
            e.is_router = is_router;
            e.timestamp_ns = now_ns;
            return;
        }
    }
    // Insert into empty slot
    for (table) |*e| {
        if (!e.valid) {
            @memcpy(&e.ip6, &ip6);
            @memcpy(&e.mac, &mac);
            e.valid = true;
            e.is_router = is_router;
            e.timestamp_ns = now_ns;
            return;
        }
    }
    // Table full — evict oldest
    var oldest_idx: usize = 0;
    var oldest_ts: u64 = table[0].timestamp_ns;
    for (table, 0..) |*e, idx| {
        if (e.timestamp_ns < oldest_ts) {
            oldest_ts = e.timestamp_ns;
            oldest_idx = idx;
        }
    }
    @memcpy(&table[oldest_idx].ip6, &ip6);
    @memcpy(&table[oldest_idx].mac, &mac);
    table[oldest_idx].is_router = is_router;
    table[oldest_idx].timestamp_ns = now_ns;
}

pub fn expire(table: *[TABLE_SIZE]NdpEntry) void {
    const now_ns = util.now();
    for (table) |*e| {
        if (e.valid and now_ns -% e.timestamp_ns > EXPIRY_NS) {
            e.valid = false;
        }
    }
}

/// Send a Neighbor Solicitation for the given target IPv6 address.
pub fn sendNeighborSolicitation(iface: Interface, target_ip6: [16]u8) void {
    const ifc = main.getIface(iface);
    var pkt: [86]u8 = undefined;
    @memset(&pkt, 0);

    // Ethernet header
    const snm = util.solicitedNodeMulticast(target_ip6);
    const dst_mac = util.multicastMac6(snm);
    @memcpy(pkt[0..6], &dst_mac);
    @memcpy(pkt[6..12], &ifc.mac);
    pkt[12] = 0x86;
    pkt[13] = 0xDD;

    // IPv6 header
    pkt[14] = 0x60; // version 6
    // payload length = 32 (24 NS + 8 source link-layer option)
    pkt[18] = 0;
    pkt[19] = 32;
    pkt[20] = 58; // next header: ICMPv6
    pkt[21] = 255; // hop limit
    @memcpy(pkt[22..38], &ifc.ip6_link_local); // source
    @memcpy(pkt[38..54], &snm); // destination: solicited-node multicast

    // ICMPv6 Neighbor Solicitation (type 135)
    pkt[54] = 135;
    pkt[55] = 0; // code
    // checksum at 56-57, filled below
    // reserved at 58-61 (already zeroed)
    @memcpy(pkt[62..78], &target_ip6); // target address

    // Source Link-Layer Address option (type 1, length 1 = 8 bytes)
    pkt[78] = 1; // type
    pkt[79] = 1; // length in units of 8 bytes
    @memcpy(pkt[80..86], &ifc.mac);

    // Compute ICMPv6 checksum
    const cs = util.computeIcmpv6Checksum(ifc.ip6_link_local, snm, pkt[54..86]);
    pkt[56] = @truncate(cs >> 8);
    pkt[57] = @truncate(cs);

    _ = ifc.txSendLocal(&pkt);
}

/// Handle an incoming NDP packet. Returns a reply packet if applicable.
pub fn handle(iface: Interface, pkt: []u8, len: u32) ?[]const u8 {
    if (len < 78) return null; // 14 eth + 40 ipv6 + 24 NS minimum
    const ifc = main.getIface(iface);
    const icmpv6_type = pkt[54];

    if (icmpv6_type == 135) {
        // Neighbor Solicitation — check if target is our address
        var target: [16]u8 = undefined;
        @memcpy(&target, pkt[62..78]);

        const is_our_addr = util.eql(&target, &ifc.ip6_link_local) or
            (ifc.ip6_global_valid and util.eql(&target, &ifc.ip6_global));
        if (!is_our_addr) return null;

        // Learn sender
        var src_ip6: [16]u8 = undefined;
        @memcpy(&src_ip6, pkt[22..38]);
        var src_mac: [6]u8 = undefined;
        @memcpy(&src_mac, pkt[6..12]);
        const ndp_tbl = if (iface == .wan) &main.wan_ndp_table else &main.lan_ndp_table;
        if (!util.isAllZeros(&src_ip6)) learn(ndp_tbl, src_ip6, src_mac, false);

        // Build Neighbor Advertisement reply
        return buildNA(ifc, src_ip6, src_mac, target);
    }

    if (icmpv6_type == 136 and len >= 78) {
        // Neighbor Advertisement — learn the mapping
        var target: [16]u8 = undefined;
        @memcpy(&target, pkt[62..78]);
        var src_mac: [6]u8 = undefined;
        // Check for Target Link-Layer Address option
        if (len >= 86 and pkt[78] == 2 and pkt[79] == 1) {
            @memcpy(&src_mac, pkt[80..86]);
        } else {
            @memcpy(&src_mac, pkt[6..12]);
        }
        const ndp_tbl = if (iface == .wan) &main.wan_ndp_table else &main.lan_ndp_table;
        const flags = pkt[58];
        learn(ndp_tbl, target, src_mac, flags & 0x80 != 0); // R flag = router
    }

    return null;
}

var na_buf: [86]u8 = undefined;

fn buildNA(
    ifc: *const @import("router").net.iface.Iface,
    dst_ip6: [16]u8,
    dst_mac: [6]u8,
    target: [16]u8,
) []const u8 {
    @memset(&na_buf, 0);

    // Ethernet
    @memcpy(na_buf[0..6], &dst_mac);
    @memcpy(na_buf[6..12], &ifc.mac);
    na_buf[12] = 0x86;
    na_buf[13] = 0xDD;

    // IPv6
    na_buf[14] = 0x60;
    na_buf[18] = 0;
    na_buf[19] = 32; // payload = 24 NA + 8 option
    na_buf[20] = 58; // ICMPv6
    na_buf[21] = 255;
    @memcpy(na_buf[22..38], &target); // source = target (our address)
    @memcpy(na_buf[38..54], &dst_ip6); // destination

    // ICMPv6 NA (type 136)
    na_buf[54] = 136;
    na_buf[55] = 0;
    // Flags: R (router) + S (solicited) + O (override)
    na_buf[58] = 0xE0;
    @memcpy(na_buf[62..78], &target);

    // Target Link-Layer Address option
    na_buf[78] = 2; // type
    na_buf[79] = 1; // length
    @memcpy(na_buf[80..86], &ifc.mac);

    // ICMPv6 checksum
    const cs = util.computeIcmpv6Checksum(target, dst_ip6, na_buf[54..86]);
    na_buf[56] = @truncate(cs >> 8);
    na_buf[57] = @truncate(cs);

    return &na_buf;
}
