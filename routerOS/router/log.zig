const lib = @import("lib");

const channel_mod = lib.channel;
const syscall = lib.syscall;

// ── Log levels ───────────────────────────────────────────────────────

pub const Level = enum(u8) {
    err = 0,
    warn = 1,
    info = 2,
    debug = 3,
};

// ── Message IDs ──────────────────────────────────────────────────────
// Each message is a fixed entry in the table below. WAN/LAN threads
// just write a u16 id + optional data — no timestamp, no string copy.

pub const Msg = enum(u16) {
    // router init / service thread
    service_started,
    nfs_connected,
    ntp_connected,
    http_connected,
    console_connected,

    // dhcp client
    dhcp_sent_discover,
    dhcp_sent_request,
    dhcp_sent_rebind,
    dhcp_offered, // data: [4]u8 ip
    dhcp_bound, // data: [4]u8 ip
    dhcp_t1_renewal,
    dhcp_t2_rebind,
    dhcp_timeout_request,
    dhcp_timeout_rebind,
    dhcp_timeout_retry,
    dhcp_lease_expired,

    // dhcpv6
    dhcpv6_sent_solicit,
    dhcpv6_received_advertise,
    dhcpv6_bound_prefix,
    dhcpv6_sent_request,
    dhcpv6_t1_renewal,
    dhcpv6_timeout_retry,

    // nat
    nat_postcondition_fail,
};

const MsgInfo = struct {
    level: Level,
    source: []const u8,
    text: []const u8,
    has_ip: bool = false,
};

const msg_table = init_msg_table();

fn init_msg_table() [@typeInfo(Msg).@"enum".fields.len]MsgInfo {
    var t: [@typeInfo(Msg).@"enum".fields.len]MsgInfo = undefined;
    t[@intFromEnum(Msg.service_started)] = .{ .level = .info, .source = "router", .text = "service thread started" };
    t[@intFromEnum(Msg.nfs_connected)] = .{ .level = .info, .source = "router", .text = "nfs channel connected" };
    t[@intFromEnum(Msg.ntp_connected)] = .{ .level = .info, .source = "router", .text = "ntp channel connected" };
    t[@intFromEnum(Msg.http_connected)] = .{ .level = .info, .source = "router", .text = "http channel connected" };
    t[@intFromEnum(Msg.console_connected)] = .{ .level = .info, .source = "router", .text = "console channel connected" };

    t[@intFromEnum(Msg.dhcp_sent_discover)] = .{ .level = .info, .source = "dhcp", .text = "sent DISCOVER" };
    t[@intFromEnum(Msg.dhcp_sent_request)] = .{ .level = .info, .source = "dhcp", .text = "sent REQUEST" };
    t[@intFromEnum(Msg.dhcp_sent_rebind)] = .{ .level = .info, .source = "dhcp", .text = "sent REBIND" };
    t[@intFromEnum(Msg.dhcp_offered)] = .{ .level = .info, .source = "dhcp", .text = "offered ", .has_ip = true };
    t[@intFromEnum(Msg.dhcp_bound)] = .{ .level = .info, .source = "dhcp", .text = "bound to ", .has_ip = true };
    t[@intFromEnum(Msg.dhcp_t1_renewal)] = .{ .level = .info, .source = "dhcp", .text = "T1 renewal" };
    t[@intFromEnum(Msg.dhcp_t2_rebind)] = .{ .level = .info, .source = "dhcp", .text = "T2 rebind" };
    t[@intFromEnum(Msg.dhcp_timeout_request)] = .{ .level = .warn, .source = "dhcp", .text = "timeout, retrying request" };
    t[@intFromEnum(Msg.dhcp_timeout_rebind)] = .{ .level = .warn, .source = "dhcp", .text = "timeout, retrying rebind" };
    t[@intFromEnum(Msg.dhcp_timeout_retry)] = .{ .level = .warn, .source = "dhcp", .text = "timeout, retrying" };
    t[@intFromEnum(Msg.dhcp_lease_expired)] = .{ .level = .warn, .source = "dhcp", .text = "lease expired, restarting" };

    t[@intFromEnum(Msg.dhcpv6_sent_solicit)] = .{ .level = .info, .source = "dhcpv6", .text = "sent SOLICIT" };
    t[@intFromEnum(Msg.dhcpv6_received_advertise)] = .{ .level = .info, .source = "dhcpv6", .text = "received ADVERTISE" };
    t[@intFromEnum(Msg.dhcpv6_bound_prefix)] = .{ .level = .info, .source = "dhcpv6", .text = "bound, prefix delegated" };
    t[@intFromEnum(Msg.dhcpv6_sent_request)] = .{ .level = .info, .source = "dhcpv6", .text = "sent REQUEST" };
    t[@intFromEnum(Msg.dhcpv6_t1_renewal)] = .{ .level = .info, .source = "dhcpv6", .text = "T1 renewal" };
    t[@intFromEnum(Msg.dhcpv6_timeout_retry)] = .{ .level = .warn, .source = "dhcpv6", .text = "timeout, retrying" };

    t[@intFromEnum(Msg.nat_postcondition_fail)] = .{ .level = .err, .source = "nat", .text = "post-condition FAIL: lookup cannot find entry" };
    return t;
}

// ── Ring buffer ──────────────────────────────────────────────────────

const RING_SIZE: u64 = 64;
const RING_MASK: u64 = RING_SIZE - 1;

pub const LogEntry = struct {
    sequence: u64 = 0,
    msg_id: u16 = 0,
    data_len: u8 = 0,
    _pad: [5]u8 = .{0} ** 5,
    data: [16]u8 = .{0} ** 16,
    // Total: 32 bytes
};

var ring: [RING_SIZE]LogEntry = .{LogEntry{}} ** RING_SIZE;
var write_pos: u64 align(8) = 0;
var read_pos: u64 = 0;
pub var dropped_count: u64 align(8) = 0;

// ── NTP wall-clock state (updated by service thread) ─────────────────

pub const MSG_TIME_SYNC: u8 = 0x11;

var ntp_unix_secs: u64 = 0;
var ntp_sync_mono_ns: u64 = 0;
var ntp_synced: bool = false;

pub fn updateNtpTime(unix_secs: u64, mono_ns: u64) void {
    ntp_unix_secs = unix_secs;
    ntp_sync_mono_ns = mono_ns;
    ntp_synced = true;
}

fn wallClockSecs() u64 {
    if (!ntp_synced) return 0;
    const now_mono: u64 = @bitCast(syscall.clock_gettime());
    const elapsed_secs = (now_mono -| ntp_sync_mono_ns) / 1_000_000_000;
    return ntp_unix_secs + elapsed_secs;
}

// ── Write buffer for formatted text (service thread only) ────────────

const MSG_LOG_WRITE: u8 = 0x10;
const WRITE_BUF_SIZE: usize = 4096;
const FLUSH_THRESHOLD: usize = 3072;
const FLUSH_INTERVAL: u32 = 1000;

var write_buf: [WRITE_BUF_SIZE]u8 = undefined;
var write_buf_pos: usize = 0;
var boot_marker_sent: bool = false;

// ── Public API (lock-free, safe from any thread) ─────────────────────
// No timestamp, no string copy — just a msg_id written to the ring.

pub fn write(msg: Msg) void {
    writeWithData(msg, &.{});
}

pub fn writeWithIp(msg: Msg, ip: [4]u8) void {
    writeWithData(msg, &ip);
}

fn writeWithData(msg: Msg, data: []const u8) void {
    const pos = @atomicRmw(u64, &write_pos, .Add, 1, .monotonic);

    const rp = @atomicLoad(u64, &read_pos, .acquire);
    if (pos -% rp >= RING_SIZE) {
        _ = @atomicRmw(u64, &dropped_count, .Add, 1, .monotonic);
        return;
    }

    const slot = &ring[pos & RING_MASK];
    slot.msg_id = @intFromEnum(msg);
    const copy_len: u8 = @intCast(@min(data.len, slot.data.len));
    slot.data_len = copy_len;
    if (copy_len > 0) {
        @memcpy(slot.data[0..copy_len], data[0..copy_len]);
    }

    @atomicStore(u64, &slot.sequence, pos + 1, .release);
}

// ── Service thread: drain ring and flush to NFS ──────────────────────

pub fn drainAndFlush(nfs_chan: *?channel_mod.Channel, loop_n: u32) void {
    // Boot marker
    if (!boot_marker_sent) {
        var marker: [64]u8 = undefined;
        var mp: usize = 0;
        mp = appendWallTimestamp(&marker, mp);
        mp = appendStr(&marker, mp, " === ROUTER BOOT ===\n");
        appendToWriteBuf(marker[0..mp]);
        boot_marker_sent = true;
    }

    var had_error = false;
    var drained: u32 = 0;

    while (drained < RING_SIZE) : (drained += 1) {
        const slot = &ring[read_pos & RING_MASK];
        const seq = @atomicLoad(u64, &slot.sequence, .acquire);
        if (seq != read_pos + 1) break;

        const info = msg_table[slot.msg_id];

        var line: [256]u8 = undefined;
        var pos: usize = 0;

        // Timestamp assigned NOW by the service thread
        pos = appendWallTimestamp(&line, pos);
        pos = appendStr(&line, pos, " ");

        const level_str: []const u8 = switch (info.level) {
            .err => "ERR  ",
            .warn => "WARN ",
            .info => "INFO ",
            .debug => "DEBUG",
        };
        pos = appendStr(&line, pos, level_str);
        pos = appendStr(&line, pos, " ");
        pos = appendStr(&line, pos, info.source);

        // Pad source to 8 chars
        var pad: usize = info.source.len;
        while (pad < 8) : (pad += 1) {
            if (pos < line.len) {
                line[pos] = ' ';
                pos += 1;
            }
        }
        pos = appendStr(&line, pos, ": ");
        pos = appendStr(&line, pos, info.text);

        // Append IP if flagged
        if (info.has_ip and slot.data_len >= 4) {
            pos = appendIp(&line, pos, slot.data[0..4].*);
        }

        pos = appendStr(&line, pos, "\n");

        syscall.write(line[0..pos]);
        appendToWriteBuf(line[0..pos]);

        if (info.level == .err) had_error = true;

        @atomicStore(u64, &slot.sequence, 0, .release);
        read_pos += 1;
    }

    // Report drops
    const drops = @atomicRmw(u64, &dropped_count, .Xchg, 0, .monotonic);
    if (drops > 0) {
        var drop_line: [64]u8 = undefined;
        var dp: usize = 0;
        dp = appendStr(&drop_line, dp, "[log] ");
        dp = appendDec(&drop_line, dp, drops);
        dp = appendStr(&drop_line, dp, " entries dropped\n");
        syscall.write(drop_line[0..dp]);
        appendToWriteBuf(drop_line[0..dp]);
    }

    const should_flush = (write_buf_pos >= FLUSH_THRESHOLD) or
        (had_error and write_buf_pos > 0) or
        (loop_n % FLUSH_INTERVAL == 0 and write_buf_pos > 0);

    if (should_flush) {
        if (nfs_chan.*) |*chan| {
            flushToNfs(chan);
        }
    }
}

fn flushToNfs(chan: *channel_mod.Channel) void {
    if (write_buf_pos == 0) return;

    var msg: [3 + WRITE_BUF_SIZE]u8 = undefined;
    const data_len = @min(write_buf_pos, WRITE_BUF_SIZE);
    msg[0] = MSG_LOG_WRITE;
    msg[1] = @truncate(data_len >> 8);
    msg[2] = @truncate(data_len);
    @memcpy(msg[3..][0..data_len], write_buf[0..data_len]);

    if (chan.send(msg[0 .. 3 + data_len])) {
        write_buf_pos = 0;
    }
}

fn appendToWriteBuf(data: []const u8) void {
    const space = WRITE_BUF_SIZE - write_buf_pos;
    const copy_len = @min(data.len, space);
    if (copy_len > 0) {
        @memcpy(write_buf[write_buf_pos..][0..copy_len], data[0..copy_len]);
        write_buf_pos += copy_len;
    }
}

// ── Formatting helpers ───────────────────────────────────────────────

fn appendWallTimestamp(buf: []u8, pos: usize) usize {
    var p = pos;
    p = appendStr(buf, p, "[");

    const wall = wallClockSecs();
    if (wall == 0) {
        // NTP not synced yet — show monotonic uptime
        const mono: u64 = @bitCast(syscall.clock_gettime());
        const secs = mono / 1_000_000_000;
        const ms = (mono % 1_000_000_000) / 1_000_000;
        p = appendStr(buf, p, "boot+");
        p = appendDec(buf, p, secs);
        p = appendStr(buf, p, ".");
        if (ms < 100) p = appendStr(buf, p, "0");
        if (ms < 10) p = appendStr(buf, p, "0");
        p = appendDec(buf, p, ms);
    } else {
        // Format as HH:MM:SS from unix timestamp
        const day_secs = wall % 86400;
        const hours = day_secs / 3600;
        const minutes = (day_secs % 3600) / 60;
        const seconds = day_secs % 60;
        if (hours < 10) p = appendStr(buf, p, "0");
        p = appendDec(buf, p, hours);
        p = appendStr(buf, p, ":");
        if (minutes < 10) p = appendStr(buf, p, "0");
        p = appendDec(buf, p, minutes);
        p = appendStr(buf, p, ":");
        if (seconds < 10) p = appendStr(buf, p, "0");
        p = appendDec(buf, p, seconds);
    }

    p = appendStr(buf, p, "]");
    return p;
}

fn appendStr(buf: []u8, pos: usize, s: []const u8) usize {
    const end = @min(pos + s.len, buf.len);
    @memcpy(buf[pos..end], s[0..(end - pos)]);
    return end;
}

fn appendDec(buf: []u8, pos: usize, val: u64) usize {
    if (val == 0) {
        if (pos < buf.len) {
            buf[pos] = '0';
            return pos + 1;
        }
        return pos;
    }
    var tmp: [20]u8 = undefined;
    var v = val;
    var i: usize = 20;
    while (v > 0) {
        i -= 1;
        tmp[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    return appendStr(buf, pos, tmp[i..20]);
}

fn appendIp(buf: []u8, pos: usize, ip: [4]u8) usize {
    var p = pos;
    for (ip, 0..) |octet, idx| {
        p = appendDec(buf, p, octet);
        if (idx < 3) p = appendStr(buf, p, ".");
    }
    return p;
}

// ── Introspection (for fuzzer invariant checks) ──────────────────────

pub fn getWritePos() u64 {
    return @atomicLoad(u64, &write_pos, .acquire);
}

pub fn getReadPos() u64 {
    return read_pos;
}

pub fn getRingSize() u64 {
    return RING_SIZE;
}

pub fn getEntrySequence(idx: u64) u64 {
    return @atomicLoad(u64, &ring[idx & RING_MASK].sequence, .acquire);
}

pub fn getEntryLevel(idx: u64) u8 {
    return @intFromEnum(msg_table[ring[idx & RING_MASK].msg_id].level);
}

pub fn reset() void {
    for (&ring) |*slot| {
        slot.* = LogEntry{};
    }
    write_pos = 0;
    read_pos = 0;
    dropped_count = 0;
    write_buf_pos = 0;
    boot_marker_sent = false;
    ntp_synced = false;
}
