const router = @import("router");

const h = router.hal.headers;
const main = router.state;
const util = router.util;

const Interface = main.Interface;

pub const TABLE_SIZE = 128;
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

    const eth = h.EthernetHeader.parseMut(&pkt) orelse unreachable;
    @memset(&eth.dst_mac, 0xFF);
    @memcpy(&eth.src_mac, &ifc.mac);
    eth.setEtherType(h.EthernetHeader.ARP);

    const arp_hdr = h.ArpHeader.parseMut(pkt[14..]) orelse unreachable;
    // hw_type = 0x0001 (Ethernet), proto_type = 0x0800 (IPv4) — raw network-order bytes
    pkt[14] = 0x00;
    pkt[15] = 0x01;
    pkt[16] = 0x08;
    pkt[17] = 0x00;
    arp_hdr.hw_len = 6;
    arp_hdr.proto_len = 4;
    arp_hdr.setOpcode(h.ArpHeader.OP_REQUEST);
    @memcpy(&arp_hdr.sender_mac, &ifc.mac);
    @memcpy(&arp_hdr.sender_ip, &ifc.ip);
    @memset(&arp_hdr.target_mac, 0);
    @memcpy(&arp_hdr.target_ip, &target_ip);
    _ = ifc.txSendLocal(&pkt, .dataplane);
}

pub fn handle(iface: Interface, pkt: []u8, len: u32) ?[]u8 {
    if (len < 42) return null;

    const arp_hdr = h.ArpHeader.parseMut(pkt[14..]) orelse return null;
    if (arp_hdr.hwType() != 0x0001) return null;
    if (arp_hdr.protoType() != 0x0800) return null;

    const ifc = main.getIface(iface);

    const op = arp_hdr.opcode();
    if (op != h.ArpHeader.OP_REQUEST and op != h.ArpHeader.OP_REPLY) return null;

    if (op == h.ArpHeader.OP_REQUEST and !util.eql(&arp_hdr.target_ip, &ifc.ip)) return null;

    if (op == h.ArpHeader.OP_REQUEST) {
        @memcpy(pkt[0..6], pkt[6..12]);
        @memcpy(pkt[6..12], &ifc.mac);
        arp_hdr.setOpcode(h.ArpHeader.OP_REPLY);

        var mac_tmp: [6]u8 = undefined;
        @memcpy(&mac_tmp, &arp_hdr.sender_mac);
        @memcpy(&arp_hdr.target_mac, &mac_tmp);
        @memcpy(&arp_hdr.sender_mac, &ifc.mac);

        var ip_tmp: [4]u8 = undefined;
        @memcpy(&ip_tmp, &arp_hdr.sender_ip);
        @memcpy(&arp_hdr.target_ip, &ip_tmp);
        @memcpy(&arp_hdr.sender_ip, &ifc.ip);

        if (len < 60) {
            @memset(pkt[42..60], 0);
            return pkt[0..60];
        }
        return pkt[0..len];
    }

    return null;
}
