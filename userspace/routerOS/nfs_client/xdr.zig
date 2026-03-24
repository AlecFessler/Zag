/// XDR (External Data Representation) encoding/decoding for NFS/RPC.
/// All values are big-endian, 4-byte aligned per RFC 4506.

pub fn writeU32(buf: []u8, pos: usize, val: u32) usize {
    if (pos + 4 > buf.len) return pos;
    buf[pos] = @truncate(val >> 24);
    buf[pos + 1] = @truncate(val >> 16);
    buf[pos + 2] = @truncate(val >> 8);
    buf[pos + 3] = @truncate(val);
    return pos + 4;
}

pub fn writeU64(buf: []u8, pos: usize, val: u64) usize {
    const p = writeU32(buf, pos, @truncate(val >> 32));
    return writeU32(buf, p, @truncate(val));
}

/// Write opaque data: [u32 length][data bytes][padding to 4-byte boundary]
pub fn writeOpaque(buf: []u8, pos: usize, data: []const u8) usize {
    var p = writeU32(buf, pos, @intCast(data.len));
    const end = p + data.len;
    if (end > buf.len) return pos;
    @memcpy(buf[p..][0..data.len], data);
    p = end;
    // Pad to 4-byte boundary
    const pad = padLen(data.len) - data.len;
    var i: usize = 0;
    while (i < pad and p < buf.len) : (i += 1) {
        buf[p] = 0;
        p += 1;
    }
    return p;
}

pub fn writeString(buf: []u8, pos: usize, s: []const u8) usize {
    return writeOpaque(buf, pos, s);
}

pub fn readU32(buf: []const u8, pos: usize) ?struct { val: u32, pos: usize } {
    if (pos + 4 > buf.len) return null;
    const val = @as(u32, buf[pos]) << 24 | @as(u32, buf[pos + 1]) << 16 |
        @as(u32, buf[pos + 2]) << 8 | buf[pos + 3];
    return .{ .val = val, .pos = pos + 4 };
}

pub fn readU64(buf: []const u8, pos: usize) ?struct { val: u64, pos: usize } {
    const hi = readU32(buf, pos) orelse return null;
    const lo = readU32(buf, hi.pos) orelse return null;
    return .{ .val = @as(u64, hi.val) << 32 | lo.val, .pos = lo.pos };
}

/// Read opaque data: returns a slice into buf and the position after padding.
pub fn readOpaque(buf: []const u8, pos: usize) ?struct { data: []const u8, pos: usize } {
    const len_r = readU32(buf, pos) orelse return null;
    const data_len: usize = len_r.val;
    const data_start = len_r.pos;
    if (data_start + data_len > buf.len) return null;
    const padded = data_start + padLen(data_len);
    return .{ .data = buf[data_start..][0..data_len], .pos = padded };
}

/// Round up to 4-byte boundary.
pub fn padLen(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}
