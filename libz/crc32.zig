const TABLE: [256]u32 = blk: {
    @setEvalBranchQuota(10000);
    var t: [256]u32 = undefined;
    for (0..256) |i| {
        var crc: u32 = @intCast(i);
        for (0..8) |_| {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
        t[i] = crc;
    }
    break :blk t;
};

pub fn update(crc: u32, data: []const u8) u32 {
    var c = crc;
    for (data) |byte| {
        c = TABLE[(c ^ byte) & 0xFF] ^ (c >> 8);
    }
    return c;
}

pub fn compute(data: []const u8) u32 {
    return update(0xFFFFFFFF, data) ^ 0xFFFFFFFF;
}
