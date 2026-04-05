const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

const Channel = channel.Channel;

pub const SHM_SIZE: u64 = 4 * syscall.PAGE4K;

// ── A→B commands (console → root) ──────────────────────────────────
pub const CMD_RELOAD: u8 = 0x01;

// ── B→A responses (root → console) ─────────────────────────────────
pub const RESP_STATUS: u8 = 0x80;
pub const RESP_OK: u8 = 0x81;
pub const RESP_ERROR: u8 = 0xFF;

const MAX_WIRE = 2048;

// ── Client (side A — console) ──────────────────────────────────────

pub const Response = union(enum) {
    status: []const u8,
    ok: void,
    err: []const u8,
};

pub const Client = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Client {
        return .{ .chan = chan };
    }

    pub fn sendReload(self: *const Client, name: []const u8) void {
        var msg: [MAX_WIRE]u8 = undefined;
        const total = 1 + name.len;
        if (total > msg.len) return;
        msg[0] = CMD_RELOAD;
        @memcpy(msg[1..][0..name.len], name);
        self.chan.sendMessage(.A, msg[0..total]) catch {};
    }

    pub fn recv(self: *const Client, buf: []u8) ?Response {
        const len = (self.chan.receiveMessage(.A, buf) catch return null) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            RESP_STATUS => Response{ .status = buf[1..len] },
            RESP_OK => Response{ .ok = {} },
            RESP_ERROR => Response{ .err = buf[1..len] },
            else => null,
        };
    }

    pub fn waitForMessage(self: *const Client, timeout_ns: u64) void {
        self.chan.waitForMessage(.A, timeout_ns);
    }
};

// ── Server (side B — root service) ─────────────────────────────────

pub const Command = union(enum) {
    reload: []const u8,
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
            CMD_RELOAD => Command{ .reload = buf[1..len] },
            else => null,
        };
    }

    pub fn sendStatus(self: *const Server, text: []const u8) void {
        var msg: [MAX_WIRE]u8 = undefined;
        const total = 1 + text.len;
        if (total > msg.len) return;
        msg[0] = RESP_STATUS;
        @memcpy(msg[1..][0..text.len], text);
        self.chan.sendMessage(.B, msg[0..total]) catch {};
    }

    pub fn sendOk(self: *const Server) void {
        self.chan.sendMessage(.B, &[_]u8{RESP_OK}) catch {};
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
