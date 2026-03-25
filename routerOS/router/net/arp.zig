const router = @import("router");

const main = router.state;
const util = router.util;

const Interface = main.Interface;

pub const TABLE_SIZE = 64;
const EXPIRY_NS: u64 = 300_000_000_000;

pub const ArpEntry = struct {
    ip: [4]u8,
    mac: [6]u8,
    valid: bool,
    timestamp_ns: u64,
};

pub const empty = ArpEntry{ .ip = .{ 0, 0, 0, 0 }, .mac = .{ 0, 0, 0, 0, 0, 0 }, .valid = false, .timestamp_ns = 0 };

pub fn lookup(table: *[TABLE_SIZE]ArpEntry, ip: [4]u8) ?[6]u8 {
    for (table) |*e| {
        if (e.valid and util.eql(&e.ip, &ip)) return e.mac;
    }
    return null;
}

pub fn learn(table: *[TABLE_SIZE]ArpEntry, ip: [4]u8, mac: [6]u8) void {
    const ts = util.now();
    for (table) |*e| {
        if (e.valid and util.eql(&e.ip, &ip)) {
            @memcpy(&e.mac, &mac);
            e.timestamp_ns = ts;
            return;
        }
    }
    for (table) |*e| {
        if (!e.valid) {
            e.ip = ip;
            @memcpy(&e.mac, &mac);
            e.valid = true;
            e.timestamp_ns = ts;
            return;
        }
    }
    // Evict oldest entry (LRU)
    var oldest_idx: usize = 0;
    var oldest_ts: u64 = table[0].timestamp_ns;
    for (table, 0..) |*e, idx| {
        if (e.timestamp_ns < oldest_ts) {
            oldest_ts = e.timestamp_ns;
            oldest_idx = idx;
        }
    }
    table[oldest_idx].ip = ip;
    @memcpy(&table[oldest_idx].mac, &mac);
    table[oldest_idx].valid = true;
    table[oldest_idx].timestamp_ns = ts;
}

pub fn expire(table: *[TABLE_SIZE]ArpEntry) void {
    const ts = util.now();
    for (table) |*e| {
        if (e.valid and ts -| e.timestamp_ns > EXPIRY_NS) {
            e.valid = false;
        }
    }
}

pub fn sendRequest(iface: Interface, target_ip: [4]u8) void {
    const ifc = main.getIface(iface);
    var pkt: [60]u8 = undefined;
    @memset(&pkt, 0);
    @memset(pkt[0..6], 0xFF);
    @memcpy(pkt[6..12], &ifc.mac);
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
    @memcpy(pkt[22..28], &ifc.mac);
    @memcpy(pkt[28..32], &ifc.ip);
    @memset(pkt[32..38], 0);
    @memcpy(pkt[38..42], &target_ip);
    _ = ifc.txSendLocal(&pkt);
}

pub fn handle(iface: Interface, pkt: []u8, len: u32) ?[]u8 {
    if (len < 42) return null;
    const arp_start = 14;
    if (util.readU16Be(pkt[arp_start..][0..2]) != 0x0001) return null;
    if (util.readU16Be(pkt[arp_start + 2 ..][0..2]) != 0x0800) return null;

    const ifc = main.getIface(iface);

    const opcode = util.readU16Be(pkt[arp_start + 6 ..][0..2]);
    if (opcode != 0x0001 and opcode != 0x0002) return null;

    if (opcode == 0x0001 and !util.eql(pkt[arp_start + 24 ..][0..4], &ifc.ip)) return null;

    if (opcode == 0x0001) {
        @memcpy(pkt[0..6], pkt[6..12]);
        @memcpy(pkt[6..12], &ifc.mac);
        util.writeU16Be(pkt[arp_start + 6 ..][0..2], 0x0002);

        var mac_tmp: [6]u8 = undefined;
        @memcpy(&mac_tmp, pkt[arp_start + 8 ..][0..6]);
        @memcpy(pkt[arp_start + 18 ..][0..6], &mac_tmp);
        @memcpy(pkt[arp_start + 8 ..][0..6], &ifc.mac);

        var ip_tmp: [4]u8 = undefined;
        @memcpy(&ip_tmp, pkt[arp_start + 14 ..][0..4]);
        @memcpy(pkt[arp_start + 24 ..][0..4], &ip_tmp);
        @memcpy(pkt[arp_start + 14 ..][0..4], &ifc.ip);

        if (len < 60) {
            @memset(pkt[42..60], 0);
            return pkt[0..60];
        }
        return pkt[0..len];
    }

    return null;
}
