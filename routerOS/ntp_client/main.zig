const lib = @import("lib");

const channel = lib.channel;
const pv = lib.perm_view;
const syscall = lib.syscall;

const Channel = channel.Channel;

// ── UDP proxy message tags (must match router/udp_fwd.zig) ──────────

const MSG_UDP_SEND: u8 = 0x01;
const MSG_UDP_RECV: u8 = 0x02;
const MSG_UDP_BIND: u8 = 0x03;
const MSG_SET_TIMEZONE: u8 = 0x04;
const MSG_TIME_SYNC: u8 = 0x11;

// ── Configuration ───────────────────────────────────────────────────

const DEFAULT_SHM_SIZE = 4 * syscall.PAGE4K;
const NTP_PORT: u16 = 123;
const LOCAL_PORT: u16 = 1230;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
const NTP_EPOCH_OFFSET: u64 = 2208988800; // seconds between 1900-01-01 and 1970-01-01
const TIMEOUT_NS: u64 = 5_000_000_000;

// ── State ───────────────────────────────────────────────────────────

var router_chan: *Channel = undefined;
var console_chan: ?*Channel = null;

var ntp_server_ip: [4]u8 = .{ 10, 0, 2, 1 };
var unix_timestamp: u64 = 0;
var sync_mono_ns: u64 = 0;
var synced: bool = false;
var sync_pending: bool = false;
var send_time_ns: u64 = 0;
var tz_offset_minutes: i16 = -360; // CST (UTC-6) default

// ── Entry point ─────────────────────────────────────────────────────

// ── Known SHM tracking ──────────────────────────────────────────────
var known_shm_handles: [32]u64 = .{0} ** 32;
var known_shm_count: u8 = 0;

fn addKnownShmHandle(h: u64) void {
    if (known_shm_count < 32) {
        known_shm_handles[known_shm_count] = h;
        known_shm_count += 1;
    }
}

fn pollNewShm(view_addr: u64) ?u64 {
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            var known = false;
            for (known_shm_handles[0..known_shm_count]) |h| {
                if (h == entry.handle) {
                    known = true;
                    break;
                }
            }
            if (!known and known_shm_count < 32) {
                known_shm_handles[known_shm_count] = entry.handle;
                known_shm_count += 1;
                return entry.handle;
            }
        }
    }
    return null;
}

pub fn main(perm_view_addr: u64) void {
    channel.perm_view_addr = perm_view_addr;

    // Broadcast as NTP_CLIENT
    channel.broadcast(@intFromEnum(lib.Protocol.ntp_client)) catch {};

    // Connect to router as side A via broadcast table
    var handle: u64 = 0;
    while (handle == 0) {
        handle = channel.findBroadcastHandle(perm_view_addr, .router) orelse 0;
        if (handle == 0) syscall.thread_yield();
    }
    const conn = Channel.connectAsA(handle, .ntp_client, DEFAULT_SHM_SIZE) orelse return;
    router_chan = conn.chan;
    addKnownShmHandle(conn.shm_handle);

    sendUdpBind(LOCAL_PORT);

    // Auto-sync on startup
    sendNtpRequest();

    while (true) {
        var router_buf: [256]u8 = undefined;
        if (router_chan.receiveMessage(.A, &router_buf) catch null) |len| {
            handleRouterMessage(router_buf[0..len]);
        } else {
            router_chan.waitForMessage(.A, 10_000_000); // 10ms
        }

        // Accept console connection (side B) via perm view polling
        if (console_chan == null) {
            if (pollNewShm(perm_view_addr)) |shm_handle| {
                console_chan = Channel.connectAsB(shm_handle, DEFAULT_SHM_SIZE);
            }
        }

        if (console_chan) |chan| {
            var cmd_buf: [128]u8 = undefined;
            if (chan.receiveMessage(.B, &cmd_buf) catch null) |len| {
                handleCommand(cmd_buf[0..len]);
            }
        }

        checkTimeout();
    }
}

// ── UDP helpers ─────────────────────────────────────────────────────

fn sendUdpBind(port: u16) void {
    var msg: [3]u8 = undefined;
    msg[0] = MSG_UDP_BIND;
    msg[1] = @truncate(port >> 8);
    msg[2] = @truncate(port);
    router_chan.sendMessage(.A, &msg) catch {};
}

fn sendTimeSync(unix_secs: u64, mono_ns: u64) void {
    // [0] = MSG_TIME_SYNC, [1..9] = unix_secs BE, [9..17] = mono_ns BE
    var msg: [17]u8 = undefined;
    msg[0] = MSG_TIME_SYNC;
    writeU64Be(msg[1..9], unix_secs);
    writeU64Be(msg[9..17], mono_ns);
    router_chan.sendMessage(.A, &msg) catch {};
}

fn writeU64Be(buf: *[8]u8, val: u64) void {
    buf[0] = @truncate(val >> 56);
    buf[1] = @truncate(val >> 48);
    buf[2] = @truncate(val >> 40);
    buf[3] = @truncate(val >> 32);
    buf[4] = @truncate(val >> 24);
    buf[5] = @truncate(val >> 16);
    buf[6] = @truncate(val >> 8);
    buf[7] = @truncate(val);
}

fn sendUdpPacket(dst_ip: [4]u8, dst_port: u16, src_port: u16, payload: []const u8) void {
    var msg: [256]u8 = undefined;
    const total = 9 + payload.len;
    if (total > msg.len) return;
    msg[0] = MSG_UDP_SEND;
    @memcpy(msg[1..5], &dst_ip);
    msg[5] = @truncate(dst_port >> 8);
    msg[6] = @truncate(dst_port);
    msg[7] = @truncate(src_port >> 8);
    msg[8] = @truncate(src_port);
    @memcpy(msg[9..][0..payload.len], payload);
    router_chan.sendMessage(.A, msg[0..total]) catch {};
}

// ── NTP protocol ────────────────────────────────────────────────────

fn sendNtpRequest() void {
    var pkt: [48]u8 = .{0} ** 48;
    // LI=0 (no warning), VN=4 (NTPv4), Mode=3 (client)
    pkt[0] = 0x23;
    sendUdpPacket(ntp_server_ip, NTP_PORT, LOCAL_PORT, &pkt);
    sync_pending = true;
    send_time_ns = now();
}

fn handleNtpResponse(payload: []const u8) void {
    if (payload.len < 48) return;
    if (!sync_pending) return;

    // Extract transmit timestamp at offset 40..44 (seconds since 1900)
    const ntp_secs: u64 = @as(u64, payload[40]) << 24 |
        @as(u64, payload[41]) << 16 |
        @as(u64, payload[42]) << 8 |
        @as(u64, payload[43]);

    if (ntp_secs < NTP_EPOCH_OFFSET) {
        sendConsole("NTP: invalid timestamp\n");
        sendEof();
        sync_pending = false;
        return;
    }

    unix_timestamp = ntp_secs - NTP_EPOCH_OFFSET;
    sync_mono_ns = now();
    synced = true;
    sync_pending = false;

    // Send time sync to router for log timestamps
    sendTimeSync(unix_timestamp, sync_mono_ns);

    // Send result to console if connected
    var buf: [80]u8 = undefined;
    var p: usize = 0;
    p = appendStr(&buf, p, "NTP: synced to ");
    p = appendIp(&buf, p, ntp_server_ip);
    p = appendStr(&buf, p, " | ");
    p = appendDateTime(&buf, p, unix_timestamp);
    p = appendStr(&buf, p, " ");
    p = appendTzLabel(&buf, p);
    p = appendStr(&buf, p, "\n");
    sendConsole(buf[0..p]);
    sendEof();
}

// ── Router message handling ─────────────────────────────────────────

fn handleRouterMessage(data: []const u8) void {
    if (data.len < 1) return;
    if (data[0] == MSG_UDP_RECV and data.len >= 9) {
        handleNtpResponse(data[9..]);
    } else if (data[0] == MSG_SET_TIMEZONE and data.len >= 3) {
        tz_offset_minutes = @bitCast([2]u8{ data[1], data[2] });
    }
}

// ── Console command handling ────────────────────────────────────────

fn handleCommand(data: []const u8) void {
    var cmd = data;
    while (cmd.len > 0 and (cmd[cmd.len - 1] == '\n' or cmd[cmd.len - 1] == '\r')) {
        cmd = cmd[0 .. cmd.len - 1];
    }

    if (eql(cmd, "sync")) {
        sendNtpRequest();
    } else if (eql(cmd, "time")) {
        if (!synced) {
            sendConsole("NTP: not synced\n");
            sendEof();
            return;
        }
        const elapsed_s = (now() -| sync_mono_ns) / 1_000_000_000;
        const current = unix_timestamp + elapsed_s;
        var buf: [64]u8 = undefined;
        var p: usize = 0;
        p = appendDateTime(&buf, p, current);
        p = appendStr(&buf, p, " ");
        p = appendTzLabel(&buf, p);
        p = appendStr(&buf, p, "\n");
        sendConsole(buf[0..p]);
        sendEof();
    } else if (startsWith(cmd, "ntpserver ")) {
        if (parseIp(cmd[10..])) |ip| {
            ntp_server_ip = ip;
            sendConsole("OK\n");
        } else {
            sendConsole("invalid IP\n");
        }
        sendEof();
    } else if (startsWith(cmd, "timezone ")) {
        if (parseTzOffset(cmd[9..])) |offset| {
            tz_offset_minutes = offset;
            var buf: [32]u8 = undefined;
            var p: usize = 0;
            p = appendStr(&buf, p, "OK ");
            p = appendTzLabel(&buf, p);
            p = appendStr(&buf, p, "\n");
            sendConsole(buf[0..p]);
        } else {
            sendConsole("invalid offset (e.g. -6, +5:30)\n");
        }
        sendEof();
    } else {
        sendConsole("NTP commands: sync, time, ntpserver <ip>, timezone <offset>\n");
        sendEof();
    }
}

// ── Timeout ─────────────────────────────────────────────────────────

fn checkTimeout() void {
    if (!sync_pending) return;
    if (send_time_ns == 0) return;
    if (now() -| send_time_ns > TIMEOUT_NS) {
        syscall.write("ntp_client: timeout\n");
        sendConsole("NTP: timeout\n");
        sendEof();
        sync_pending = false;
    }
}

// ── Response helpers ────────────────────────────────────────────────

fn sendConsole(msg: []const u8) void {
    if (console_chan) |chan| {
        chan.sendMessage(.B, msg) catch {};
    }
}

fn sendEof() void {
    if (console_chan) |chan| {
        chan.sendMessage(.B, &[_]u8{}) catch {};
    }
}

// ── Date/time formatting ────────────────────────────────────────────

fn appendDateTime(buf: []u8, start: usize, timestamp: u64) usize {
    // Apply timezone offset
    const offset_secs: i64 = @as(i64, tz_offset_minutes) * 60;
    const adjusted: u64 = if (offset_secs >= 0)
        timestamp +% @as(u64, @intCast(offset_secs))
    else
        timestamp -% @as(u64, @intCast(-offset_secs));

    var p = start;
    var days: u64 = adjusted / 86400;
    const day_secs = adjusted % 86400;
    const hours = day_secs / 3600;
    const mins = (day_secs % 3600) / 60;
    const secs = day_secs % 60;

    // Compute year/month/day from days since 1970-01-01
    var year: u64 = 1970;
    while (true) {
        const ydays: u64 = if (isLeapYear(year)) 366 else 365;
        if (days < ydays) break;
        days -= ydays;
        year += 1;
    }

    const leap = isLeapYear(year);
    const month_days = [12]u64{
        31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    };
    var month: u64 = 1;
    for (month_days) |md| {
        if (days < md) break;
        days -= md;
        month += 1;
    }
    const day = days + 1;

    p += appendDec4(buf[p..], year);
    if (p < buf.len) {
        buf[p] = '-';
        p += 1;
    }
    p += appendDec2(buf[p..], month);
    if (p < buf.len) {
        buf[p] = '-';
        p += 1;
    }
    p += appendDec2(buf[p..], day);
    if (p < buf.len) {
        buf[p] = ' ';
        p += 1;
    }
    p += appendDec2(buf[p..], hours);
    if (p < buf.len) {
        buf[p] = ':';
        p += 1;
    }
    p += appendDec2(buf[p..], mins);
    if (p < buf.len) {
        buf[p] = ':';
        p += 1;
    }
    p += appendDec2(buf[p..], secs);
    return p;
}

fn isLeapYear(y: u64) bool {
    return (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0);
}

fn appendDec4(buf: []u8, val: u64) usize {
    if (buf.len < 4) return 0;
    buf[0] = '0' + @as(u8, @truncate((val / 1000) % 10));
    buf[1] = '0' + @as(u8, @truncate((val / 100) % 10));
    buf[2] = '0' + @as(u8, @truncate((val / 10) % 10));
    buf[3] = '0' + @as(u8, @truncate(val % 10));
    return 4;
}

fn appendDec2(buf: []u8, val: u64) usize {
    if (buf.len < 2) return 0;
    buf[0] = '0' + @as(u8, @truncate((val / 10) % 10));
    buf[1] = '0' + @as(u8, @truncate(val % 10));
    return 2;
}

// ── Timezone helpers ─────────────────────────────────────────────────

fn appendTzLabel(buf: []u8, start: usize) usize {
    var p = start;
    if (tz_offset_minutes == 0) {
        p = appendStr(buf, p, "UTC");
        return p;
    }
    p = appendStr(buf, p, "UTC");
    const abs_mins: u16 = if (tz_offset_minutes < 0) @intCast(-tz_offset_minutes) else @intCast(tz_offset_minutes);
    const hrs = abs_mins / 60;
    const mins = abs_mins % 60;
    if (tz_offset_minutes < 0) {
        if (p < buf.len) {
            buf[p] = '-';
            p += 1;
        }
    } else {
        if (p < buf.len) {
            buf[p] = '+';
            p += 1;
        }
    }
    p = appendDecU8(buf, p, @intCast(hrs));
    if (mins > 0) {
        if (p < buf.len) {
            buf[p] = ':';
            p += 1;
        }
        p += appendDec2(buf[p..], mins);
    }
    return p;
}

fn parseTzOffset(s: []const u8) ?i16 {
    if (s.len == 0) return null;
    var i: usize = 0;
    var negative = false;
    if (s[0] == '-') {
        negative = true;
        i += 1;
    } else if (s[0] == '+') {
        i += 1;
    }
    // Parse hours
    var hrs: i16 = 0;
    var digits: usize = 0;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
        hrs = hrs * 10 + @as(i16, s[i] - '0');
        digits += 1;
    }
    if (digits == 0 or hrs > 14) return null;
    // Optional :MM
    var mins: i16 = 0;
    if (i < s.len and s[i] == ':') {
        i += 1;
        var mdigits: usize = 0;
        while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
            mins = mins * 10 + @as(i16, s[i] - '0');
            mdigits += 1;
        }
        if (mdigits == 0 or mins > 59) return null;
    }
    const total = hrs * 60 + mins;
    return if (negative) -total else total;
}

// ── Utility ─────────────────────────────────────────────────────────

fn now() u64 {
    return @bitCast(syscall.clock_gettime());
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn startsWith(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    for (s[0..prefix.len], prefix) |a, b| {
        if (a != b) return false;
    }
    return true;
}

fn appendStr(buf: []u8, start: usize, s: []const u8) usize {
    const end = @min(start + s.len, buf.len);
    @memcpy(buf[start..end], s[0..(end - start)]);
    return end;
}

fn appendIp(buf: []u8, start: usize, ip: [4]u8) usize {
    var p = start;
    for (ip, 0..) |octet, i| {
        if (i > 0 and p < buf.len) {
            buf[p] = '.';
            p += 1;
        }
        p = appendDecU8(buf, p, octet);
    }
    return p;
}

fn appendDecU8(buf: []u8, start: usize, val: u8) usize {
    var p = start;
    if (val >= 100 and p < buf.len) {
        buf[p] = '0' + val / 100;
        p += 1;
    }
    if (val >= 10 and p < buf.len) {
        buf[p] = '0' + (val / 10) % 10;
        p += 1;
    }
    if (p < buf.len) {
        buf[p] = '0' + val % 10;
        p += 1;
    }
    return p;
}

fn parseIp(s: []const u8) ?[4]u8 {
    var ip: [4]u8 = .{ 0, 0, 0, 0 };
    var octet: u16 = 0;
    var idx: u8 = 0;
    var digits: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (digits == 0 or idx >= 3 or octet > 255) return null;
            ip[idx] = @truncate(octet);
            idx += 1;
            octet = 0;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            digits += 1;
        } else {
            break;
        }
    }
    if (digits == 0 or idx != 3 or octet > 255) return null;
    ip[3] = @truncate(octet);
    return ip;
}
