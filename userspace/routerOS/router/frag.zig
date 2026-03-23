const util = @import("util.zig");

pub const TABLE_SIZE = 16;
const EXPIRY_NS: u64 = 30_000_000_000;

pub const FragEntry = struct {
    valid: bool,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    ip_id: u16,
    protocol: u8,
    first_frag_sport: u16,
    timestamp_ns: u64,
};

pub const empty = FragEntry{
    .valid = false, .src_ip = .{ 0, 0, 0, 0 }, .dst_ip = .{ 0, 0, 0, 0 },
    .ip_id = 0, .protocol = 0, .first_frag_sport = 0, .timestamp_ns = 0,
};

pub fn learn(table: *[TABLE_SIZE]FragEntry, src_ip: [4]u8, dst_ip: [4]u8, ip_id: u16, protocol: u8, sport: u16) void {
    for (table) |*f| {
        if (f.valid and f.ip_id == ip_id and util.eql(&f.src_ip, &src_ip)) {
            f.timestamp_ns = util.now();
            return;
        }
    }
    for (table) |*f| {
        if (!f.valid) {
            f.* = .{ .valid = true, .src_ip = src_ip, .dst_ip = dst_ip,
                .ip_id = ip_id, .protocol = protocol, .first_frag_sport = sport, .timestamp_ns = util.now() };
            return;
        }
    }
    table[0] = .{ .valid = true, .src_ip = src_ip, .dst_ip = dst_ip,
        .ip_id = ip_id, .protocol = protocol, .first_frag_sport = sport, .timestamp_ns = util.now() };
}

pub fn lookup(table: *[TABLE_SIZE]FragEntry, src_ip: [4]u8, ip_id: u16) ?u16 {
    for (table) |*f| {
        if (f.valid and f.ip_id == ip_id and util.eql(&f.src_ip, &src_ip)) {
            f.timestamp_ns = util.now();
            return f.first_frag_sport;
        }
    }
    return null;
}

pub fn expire(table: *[TABLE_SIZE]FragEntry) void {
    const ts = util.now();
    for (table) |*f| {
        if (f.valid and ts -| f.timestamp_ns > EXPIRY_NS) {
            f.valid = false;
        }
    }
}
