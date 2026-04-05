const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

const Channel = channel.Channel;

pub const SHM_SIZE: u64 = 4 * syscall.PAGE4K;

// ── A→B commands ──────────────────────────────────────────��─────────
pub const CMD_TEXT: u8 = 0x01;
pub const CMD_DATA: u8 = 0x02;
pub const CMD_DATA_END: u8 = 0x03;

// ── B→A responses ───────────────────────────────────────────────────
pub const RESP_TEXT: u8 = 0x80;
pub const RESP_END: u8 = 0x81;
pub const RESP_ACK: u8 = 0x82;
pub const RESP_ERROR: u8 = 0xFF;

const MAX_WIRE = 2048;

// ── Client (side A) ─────────────────────────────────────────────────

pub const Response = union(enum) {
    text: []const u8,
    end: void,
    ack: []const u8,
    err: []const u8,
};

pub const Client = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Client {
        return .{ .chan = chan };
    }

    pub fn sendCommand(self: *const Client, text: []const u8) void {
        var msg: [MAX_WIRE]u8 = undefined;
        const total = 1 + text.len;
        if (total > msg.len) return;
        msg[0] = CMD_TEXT;
        @memcpy(msg[1..][0..text.len], text);
        self.chan.sendMessage(.A, msg[0..total]) catch {};
    }

    pub fn sendData(self: *const Client, data: []const u8) void {
        var msg: [MAX_WIRE]u8 = undefined;
        const total = 1 + data.len;
        if (total > msg.len) return;
        msg[0] = CMD_DATA;
        @memcpy(msg[1..][0..data.len], data);
        self.chan.sendMessage(.A, msg[0..total]) catch {};
    }

    pub fn sendDataEnd(self: *const Client) void {
        self.chan.sendMessage(.A, &[_]u8{CMD_DATA_END}) catch {};
    }

    pub fn recv(self: *const Client, buf: []u8) ?Response {
        const len = (self.chan.receiveMessage(.A, buf) catch return null) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            RESP_TEXT => Response{ .text = buf[1..len] },
            RESP_END => Response{ .end = {} },
            RESP_ACK => Response{ .ack = buf[1..len] },
            RESP_ERROR => Response{ .err = buf[1..len] },
            else => null,
        };
    }

    pub fn waitForMessage(self: *const Client, timeout_ns: u64) void {
        self.chan.waitForMessage(.A, timeout_ns);
    }
};

// ── Server (side B) ──────────────────────────────────────────────────

pub const Command = union(enum) {
    text: []const u8,
    data: []const u8,
    data_end: void,
};

pub const Server = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Server {
        return .{ .chan = chan };
    }

    pub fn recvCommand(self: *const Server, buf: []u8) ?Command {
        const len = (self.chan.receiveMessage(.B, buf) catch return null) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            CMD_TEXT => Command{ .text = buf[1..len] },
            CMD_DATA => Command{ .data = buf[1..len] },
            CMD_DATA_END => Command{ .data_end = {} },
            else => null,
        };
    }

    pub fn sendText(self: *const Server, text: []const u8) void {
        var msg: [MAX_WIRE]u8 = undefined;
        const total = 1 + text.len;
        if (total > msg.len) return;
        msg[0] = RESP_TEXT;
        @memcpy(msg[1..][0..text.len], text);
        self.chan.sendMessage(.B, msg[0..total]) catch {};
    }

    pub fn sendEnd(self: *const Server) void {
        self.chan.sendMessage(.B, &[_]u8{RESP_END}) catch {};
    }

    pub fn sendAck(self: *const Server, text: []const u8) void {
        var msg: [MAX_WIRE]u8 = undefined;
        const total = 1 + text.len;
        if (total > msg.len) return;
        msg[0] = RESP_ACK;
        @memcpy(msg[1..][0..text.len], text);
        self.chan.sendMessage(.B, msg[0..total]) catch {};
    }

    pub fn sendError(self: *const Server, text: []const u8) void {
        var msg: [MAX_WIRE]u8 = undefined;
        const total = 1 + text.len;
        if (total > msg.len) return;
        msg[0] = RESP_ERROR;
        @memcpy(msg[1..][0..text.len], text);
        self.chan.sendMessage(.B, msg[0..total]) catch {};
    }

    pub fn waitForMessage(self: *const Server, timeout_ns: u64) void {
        self.chan.waitForMessage(.B, timeout_ns);
    }
};
