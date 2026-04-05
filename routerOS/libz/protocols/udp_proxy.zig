const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

const Channel = channel.Channel;

pub const SHM_SIZE: u64 = 4 * syscall.PAGE4K;

// ── A→B commands ────────────────────────────────────────────────────
pub const CMD_UDP_SEND: u8 = 0x01;
pub const CMD_UDP_BIND: u8 = 0x03;

// ── B→A responses ───────────────────────────────────────────────────
pub const RESP_UDP_RECV: u8 = 0x02;

// ── Types ───────────────────────────────────────────────────────────

pub const UdpPacket = struct {
    src_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
};

// ── Client (side A — NFS/NTP connecting to router) ──────────────────

pub const Client = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Client {
        return .{ .chan = chan };
    }

    pub fn sendUdp(self: *const Client, dst_ip: [4]u8, dst_port: u16, src_port: u16, payload: []const u8) void {
        var msg: [256]u8 = undefined;
        const total = 9 + payload.len;
        if (total > msg.len) return;
        msg[0] = CMD_UDP_SEND;
        @memcpy(msg[1..5], &dst_ip);
        msg[5] = @truncate(dst_port >> 8);
        msg[6] = @truncate(dst_port);
        msg[7] = @truncate(src_port >> 8);
        msg[8] = @truncate(src_port);
        @memcpy(msg[9..][0..payload.len], payload);
        self.chan.sendMessage(.A, msg[0..total]) catch {};
    }

    pub fn bindPort(self: *const Client, port: u16) void {
        var msg: [3]u8 = undefined;
        msg[0] = CMD_UDP_BIND;
        msg[1] = @truncate(port >> 8);
        msg[2] = @truncate(port);
        self.chan.sendMessage(.A, &msg) catch {};
    }

    pub fn recv(self: *const Client, buf: []u8) ?UdpPacket {
        const len = (self.chan.receiveMessage(.A, buf) catch return null) orelse return null;
        if (len < 9 or buf[0] != RESP_UDP_RECV) return null;
        return UdpPacket{
            .src_ip = .{ buf[1], buf[2], buf[3], buf[4] },
            .src_port = @as(u16, buf[5]) << 8 | buf[6],
            .dst_port = @as(u16, buf[7]) << 8 | buf[8],
            .payload = buf[9..len],
        };
    }

    pub fn recvRaw(self: *const Client, buf: []u8) ?[]const u8 {
        const len = (self.chan.receiveMessage(.A, buf) catch return null) orelse return null;
        if (len < 1) return null;
        return buf[0..len];
    }

    pub fn sendRaw(self: *const Client, msg: []const u8) void {
        self.chan.sendMessage(.A, msg) catch {};
    }

    pub fn waitForMessage(self: *const Client, timeout_ns: u64) void {
        self.chan.waitForMessage(.A, timeout_ns);
    }
};

// ── Server (side B — router) ────────────────────────────────────────

pub const Server = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Server {
        return .{ .chan = chan };
    }

    pub fn sendUdpRecv(self: *const Server, src_ip: [4]u8, src_port: u16, dst_port: u16, payload: []const u8) void {
        var msg: [2048]u8 = undefined;
        const total = 9 + payload.len;
        if (total > msg.len) return;
        msg[0] = RESP_UDP_RECV;
        @memcpy(msg[1..5], &src_ip);
        msg[5] = @truncate(src_port >> 8);
        msg[6] = @truncate(src_port);
        msg[7] = @truncate(dst_port >> 8);
        msg[8] = @truncate(dst_port);
        @memcpy(msg[9..][0..payload.len], payload);
        self.chan.sendMessage(.B, msg[0..total]) catch {};
    }

    pub fn recvRaw(self: *const Server, buf: []u8) ?[]const u8 {
        const len = (self.chan.receiveMessage(.B, buf) catch return null) orelse return null;
        if (len < 1) return null;
        return buf[0..len];
    }

    pub fn waitForMessage(self: *const Server, timeout_ns: u64) void {
        self.chan.waitForMessage(.B, timeout_ns);
    }
};
