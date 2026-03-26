const router = @import("router");

const arp = router.net.arp;
const h = router.net.headers;
const main = router.state;
const util = router.util;

pub const RELAY_SIZE = 256;
pub const DNS_PORT: u16 = 53;

// ── Cache constants ─────────────────────────────────────────────────────
pub const CACHE_SIZE = 64;
pub const MAX_QUESTION_LEN = 64;
pub const MAX_DNS_PAYLOAD = 512;

// ── Relay types ─────────────────────────────────────────────────────────

pub const DnsRelay = struct {
    valid: bool,
    client_ip: [4]u8,
    client_mac: [6]u8,
    client_port: u16,
    query_id: u16,
    relay_id: u16,
    timestamp_ns: u64,
};

pub const empty = DnsRelay{
    .valid = false,
    .client_ip = .{ 0, 0, 0, 0 },
    .client_mac = .{ 0, 0, 0, 0, 0, 0 },
    .client_port = 0,
    .query_id = 0,
    .relay_id = 0,
    .timestamp_ns = 0,
};

// ── Cache types ─────────────────────────────────────────────────────────

pub const DnsCacheEntry = struct {
    valid: bool,
    question: [MAX_QUESTION_LEN]u8,
    question_len: u16,
    dns_payload: [MAX_DNS_PAYLOAD]u8,
    dns_payload_len: u16,
    min_ttl_secs: u32,
    cached_at_ns: u64,
    hit_count: u32,
};

pub const empty_cache = DnsCacheEntry{
    .valid = false,
    .question = .{0} ** MAX_QUESTION_LEN,
    .question_len = 0,
    .dns_payload = .{0} ** MAX_DNS_PAYLOAD,
    .dns_payload_len = 0,
    .min_ttl_secs = 0,
    .cached_at_ns = 0,
    .hit_count = 0,
};

// ── Packet handling ─────────────────────────────────────────────────────

pub fn handleFromLan(pkt: []u8, len: u32) void {
    if (len < 34) return;

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;
    if (ip.protocol != h.Ipv4Header.PROTO_UDP) return;

    const udp = h.UdpHeader.parseMut(pkt[udp_start..]) orelse return;
    if (udp.dstPort() != DNS_PORT) return;

    const src_port = udp.srcPort();
    var client_ip: [4]u8 = undefined;
    @memcpy(&client_ip, &ip.src_ip);
    var client_mac: [6]u8 = undefined;
    @memcpy(&client_mac, pkt[6..12]);

    const dns_start = udp_start + 8;
    if (dns_start + 2 > len) return;
    const query_id = util.readU16Be(pkt[dns_start..][0..2]);

    // Cache lookup — serve from cache if possible
    const dns_data = pkt[dns_start..len];
    if (dns_data.len >= 12) {
        if (extractQuestion(dns_data)) |question| {
            if (cacheLookup(question)) |entry| {
                sendCachedResponse(entry, query_id, client_ip, client_mac, src_port);
                return;
            }
        }
    }

    // Cache miss — relay to upstream
    const relay_id = main.next_dns_id;
    main.next_dns_id +%= 1;
    if (main.next_dns_id == 0) main.next_dns_id = 1;

    var slot: ?*DnsRelay = null;
    var oldest_idx: usize = 0;
    var oldest_ts: u64 = util.now();
    for (&main.dns_relays, 0..) |*r, i| {
        if (!r.valid) {
            slot = r;
            break;
        }
        if (r.timestamp_ns < oldest_ts) {
            oldest_ts = r.timestamp_ns;
            oldest_idx = i;
        }
    }
    if (slot == null) slot = &main.dns_relays[oldest_idx];

    slot.?.* = .{
        .valid = true,
        .client_ip = client_ip,
        .client_mac = client_mac,
        .client_port = src_port,
        .query_id = query_id,
        .relay_id = relay_id,
        .timestamp_ns = util.now(),
    };

    util.writeU16Be(pkt[dns_start..][0..2], relay_id);

    // Use WAN gateway MAC as next-hop (always known after boot ARP exchange)
    // rather than looking up the upstream DNS IP which may not be in ARP table
    const gateway_mac = arp.lookup(&main.wan_iface.arp_table, main.wan_gateway) orelse {
        arp.sendRequest(.wan, main.wan_gateway);
        return;
    };

    @memcpy(pkt[0..6], &gateway_mac);
    @memcpy(pkt[6..12], &main.wan_iface.mac);
    @memcpy(&ip.src_ip, &main.wan_iface.ip);
    @memcpy(&ip.dst_ip, &main.upstream_dns);

    udp.setSrcPort(relay_id);

    udp.zeroChecksum();

    ip.computeAndSetChecksum(pkt);

    main.wan_iface.stats.tx_packets += 1;
    main.wan_iface.stats.tx_bytes += len;
    _ = main.wan_iface.txSendLocal(pkt[0..len]);
}

pub fn handleFromWan(pkt: []u8, len: u32) void {
    if (!main.has_lan) return;
    if (len < 34) return;

    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;
    if (ip.protocol != h.Ipv4Header.PROTO_UDP) return;

    const udp = h.UdpHeader.parseMut(pkt[udp_start..]) orelse return;
    if (udp.srcPort() != DNS_PORT) return;

    const dns_start = udp_start + 8;
    if (dns_start + 2 > len) return;
    const resp_id = util.readU16Be(pkt[dns_start..][0..2]);

    for (&main.dns_relays) |*r| {
        if (r.valid and r.relay_id == resp_id) {
            util.writeU16Be(pkt[dns_start..][0..2], r.query_id);

            // Cache the response before sending to client
            const dns_resp = pkt[dns_start..len];
            if (dns_resp.len >= 12 and dns_resp.len <= MAX_DNS_PAYLOAD) {
                // Only cache successful responses (QR=1, RCODE=0)
                if (dns_resp[2] & 0x80 != 0 and dns_resp[3] & 0x0F == 0) {
                    if (extractQuestion(dns_resp)) |question| {
                        if (findMinTtl(dns_resp)) |min_ttl| {
                            cacheStore(question, dns_resp, min_ttl);
                        }
                    }
                }
            }

            @memcpy(pkt[0..6], &r.client_mac);
            @memcpy(pkt[6..12], &main.lan_iface.mac);
            @memcpy(&ip.src_ip, &main.lan_iface.ip);
            @memcpy(&ip.dst_ip, &r.client_ip);

            udp.setDstPort(r.client_port);
            udp.setSrcPort(DNS_PORT);

            udp.zeroChecksum();

            ip.computeAndSetChecksum(pkt);

            main.lan_iface.stats.tx_packets += 1;
            main.lan_iface.stats.tx_bytes += len;
            _ = main.lan_iface.txSendLocal(pkt[0..len]);

            r.valid = false;
            return;
        }
    }
}

// ── DNS parsing helpers ─────────────────────────────────────────────────

/// Extract the question section from DNS data (starting at DNS header).
/// Returns the question bytes (after the 12-byte header), or null if malformed.
/// Only handles single-question queries (QDCOUNT=1).
fn extractQuestion(dns_data: []const u8) ?[]const u8 {
    if (dns_data.len < 12) return null;
    const qdcount = util.readU16Be(dns_data[4..6]);
    if (qdcount != 1) return null;

    var pos: usize = 12;
    // Walk labels
    while (pos < dns_data.len) {
        const label_len = dns_data[pos];
        if (label_len == 0) {
            pos += 1;
            break;
        }
        if (label_len & 0xC0 == 0xC0) return null; // compression in question = malformed
        if (label_len > 63) return null;
        pos += 1 + @as(usize, label_len);
    } else return null;

    // QTYPE (2) + QCLASS (2)
    if (pos + 4 > dns_data.len) return null;
    pos += 4;

    return dns_data[12..pos];
}

/// Skip a DNS name (handling compression pointers). Returns position after the name.
fn skipName(data: []const u8, start: usize) ?usize {
    var pos = start;
    while (pos < data.len) {
        const b = data[pos];
        if (b == 0) return pos + 1;
        if (b & 0xC0 == 0xC0) return pos + 2;
        if (b > 63) return null;
        pos += 1 + @as(usize, b);
    }
    return null;
}

/// Find the minimum TTL across all answer RRs. Returns null if unparseable or no answers.
fn findMinTtl(dns_data: []const u8) ?u32 {
    if (dns_data.len < 12) return null;
    const qdcount = util.readU16Be(dns_data[4..6]);
    const ancount = util.readU16Be(dns_data[6..8]);
    if (ancount == 0) return null;

    var pos: usize = 12;

    // Skip question section(s)
    var q: u16 = 0;
    while (q < qdcount) : (q += 1) {
        pos = skipName(dns_data, pos) orelse return null;
        if (pos + 4 > dns_data.len) return null;
        pos += 4;
    }

    // Parse answer RRs for TTL
    var min_ttl: u32 = 0xFFFFFFFF;
    var a: u16 = 0;
    while (a < ancount) : (a += 1) {
        pos = skipName(dns_data, pos) orelse return null;
        if (pos + 10 > dns_data.len) return null;
        const ttl = readU32Be(dns_data[pos + 4 ..][0..4]);
        const rdlength = util.readU16Be(dns_data[pos + 8 ..][0..2]);
        if (ttl < min_ttl) min_ttl = ttl;
        pos += 10 + @as(usize, rdlength);
        if (pos > dns_data.len) return null;
    }
    return min_ttl;
}

/// Adjust TTL fields in a cached DNS response by subtracting elapsed seconds.
/// Returns false if any TTL would expire (entry should be invalidated).
fn adjustTtls(dns_data: []u8, elapsed_secs: u32) bool {
    if (dns_data.len < 12) return false;
    const qdcount = util.readU16Be(dns_data[4..6]);
    const ancount = util.readU16Be(dns_data[6..8]);

    var pos: usize = 12;
    var q: u16 = 0;
    while (q < qdcount) : (q += 1) {
        pos = skipName(dns_data, pos) orelse return false;
        if (pos + 4 > dns_data.len) return false;
        pos += 4;
    }

    var a: u16 = 0;
    while (a < ancount) : (a += 1) {
        pos = skipName(dns_data, pos) orelse return false;
        if (pos + 10 > dns_data.len) return false;
        const ttl = readU32Be(dns_data[pos + 4 ..][0..4]);
        if (ttl <= elapsed_secs) return false;
        writeU32Be(dns_data[pos + 4 ..][0..4], ttl - elapsed_secs);
        const rdlength = util.readU16Be(dns_data[pos + 8 ..][0..2]);
        pos += 10 + @as(usize, rdlength);
        if (pos > dns_data.len) return false;
    }
    return true;
}

fn readU32Be(buf: []const u8) u32 {
    return @as(u32, buf[0]) << 24 | @as(u32, buf[1]) << 16 | @as(u32, buf[2]) << 8 | buf[3];
}

fn writeU32Be(buf: []u8, val: u32) void {
    buf[0] = @truncate(val >> 24);
    buf[1] = @truncate(val >> 16);
    buf[2] = @truncate(val >> 8);
    buf[3] = @truncate(val);
}

// ── Cache operations ────────────────────────────────────────────────────

fn cacheLookup(question: []const u8) ?*DnsCacheEntry {
    const now_ns = util.now();
    for (&main.dns_cache) |*entry| {
        if (!entry.valid) continue;
        if (entry.question_len != question.len) continue;
        if (!util.eql(entry.question[0..entry.question_len], question)) continue;
        const elapsed_ns = now_ns -| entry.cached_at_ns;
        const elapsed_secs: u32 = @intCast(@min(elapsed_ns / 1_000_000_000, 0xFFFFFFFF));
        if (elapsed_secs >= entry.min_ttl_secs) {
            entry.valid = false;
            continue;
        }
        return entry;
    }
    return null;
}

fn cacheStore(question: []const u8, dns_payload: []const u8, min_ttl: u32) void {
    if (question.len > MAX_QUESTION_LEN) return;
    if (dns_payload.len > MAX_DNS_PAYLOAD) return;
    if (min_ttl == 0) return;

    // Check for existing entry with same question (update it)
    for (&main.dns_cache) |*entry| {
        if (!entry.valid) continue;
        if (entry.question_len == question.len and
            util.eql(entry.question[0..entry.question_len], question))
        {
            entry.dns_payload_len = @intCast(dns_payload.len);
            @memcpy(entry.dns_payload[0..dns_payload.len], dns_payload);
            entry.min_ttl_secs = min_ttl;
            entry.cached_at_ns = util.now();
            entry.hit_count = 0;
            return;
        }
    }

    // Find a free slot or evict oldest
    var slot: ?*DnsCacheEntry = null;
    var best_idx: usize = 0;
    var best_score: u64 = 0xFFFFFFFFFFFFFFFF;
    for (&main.dns_cache, 0..) |*entry, i| {
        if (!entry.valid) {
            slot = entry;
            break;
        }
        const score = entry.cached_at_ns +| (@as(u64, entry.hit_count) * 1_000_000_000);
        if (score < best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    if (slot == null) slot = &main.dns_cache[best_idx];

    slot.?.* = .{
        .valid = true,
        .question = .{0} ** MAX_QUESTION_LEN,
        .question_len = @intCast(question.len),
        .dns_payload = .{0} ** MAX_DNS_PAYLOAD,
        .dns_payload_len = @intCast(dns_payload.len),
        .min_ttl_secs = min_ttl,
        .cached_at_ns = util.now(),
        .hit_count = 0,
    };
    @memcpy(slot.?.question[0..question.len], question);
    @memcpy(slot.?.dns_payload[0..dns_payload.len], dns_payload);
}

/// Expire stale cache entries. Called from periodicMaintenance().
pub fn expireCache() void {
    const now_ns = util.now();
    for (&main.dns_cache) |*entry| {
        if (!entry.valid) continue;
        const elapsed_ns = now_ns -| entry.cached_at_ns;
        const elapsed_secs: u32 = @intCast(@min(elapsed_ns / 1_000_000_000, 0xFFFFFFFF));
        if (elapsed_secs >= entry.min_ttl_secs) {
            entry.valid = false;
        }
    }
}

/// Construct and send a cached DNS response to the requesting LAN client.
fn sendCachedResponse(
    entry: *DnsCacheEntry,
    query_id: u16,
    client_ip: [4]u8,
    client_mac: [6]u8,
    client_port: u16,
) void {
    var buf: [14 + 20 + 8 + MAX_DNS_PAYLOAD]u8 = undefined;
    const dns_len = entry.dns_payload_len;
    const udp_len: u16 = 8 + dns_len;
    const ip_total: u16 = 20 + udp_len;
    const frame_len: u32 = 14 + @as(u32, ip_total);

    // Ethernet
    @memcpy(buf[0..6], &client_mac);
    @memcpy(buf[6..12], &main.lan_iface.mac);
    buf[12] = 0x08;
    buf[13] = 0x00;

    // IPv4 (20 bytes, no options)
    buf[14] = 0x45;
    buf[15] = 0x00;
    util.writeU16Be(buf[16..18], ip_total);
    buf[18] = 0;
    buf[19] = 0;
    buf[20] = 0x40;
    buf[21] = 0x00;
    buf[22] = 64;
    buf[23] = 17; // UDP
    buf[24] = 0;
    buf[25] = 0;
    @memcpy(buf[26..30], &main.lan_iface.ip);
    @memcpy(buf[30..34], &client_ip);

    // IP checksum
    var sum: u32 = 0;
    var i: usize = 14;
    while (i < 34) : (i += 2) {
        sum += @as(u32, buf[i]) << 8 | @as(u32, buf[i + 1]);
    }
    while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    const cksum: u16 = @truncate(~sum);
    util.writeU16Be(buf[24..26], cksum);

    // UDP
    util.writeU16Be(buf[34..36], DNS_PORT);
    util.writeU16Be(buf[36..38], client_port);
    util.writeU16Be(buf[38..40], udp_len);
    buf[40] = 0;
    buf[41] = 0; // checksum zeroed

    // DNS payload
    @memcpy(buf[42..][0..dns_len], entry.dns_payload[0..dns_len]);

    // Rewrite transaction ID
    util.writeU16Be(buf[42..44], query_id);

    // Adjust TTLs for elapsed time
    const elapsed_ns = util.now() -| entry.cached_at_ns;
    const elapsed_secs: u32 = @intCast(@min(elapsed_ns / 1_000_000_000, 0xFFFFFFFF));
    if (!adjustTtls(buf[42..][0..dns_len], elapsed_secs)) {
        entry.valid = false;
        return;
    }

    entry.hit_count +|= 1;

    main.lan_iface.stats.tx_packets += 1;
    main.lan_iface.stats.tx_bytes += frame_len;
    _ = main.lan_iface.txSendLocal(buf[0..frame_len]);
}
