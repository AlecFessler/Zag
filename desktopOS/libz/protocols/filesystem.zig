const lib = @import("lib");

const Channel = lib.channel.Channel;
const Protocol = lib.Protocol;
const syscall = lib.syscall;

pub const protocol_id: Protocol = .filesystem;

// ── Commands (A→B, client → server) ─────────────────────────────────
const CMD_MKDIR: u8 = 0x01;
const CMD_RMDIR: u8 = 0x02;
const CMD_MKFILE: u8 = 0x03;
const CMD_RMFILE: u8 = 0x04;
const CMD_OPEN: u8 = 0x05;
const CMD_WRITE: u8 = 0x06;
const CMD_CLOSE: u8 = 0x07;
const CMD_LS: u8 = 0x08;
const CMD_READ: u8 = 0x09;

// ── Responses (B→A, server → client) ────────────────────────────────
const RESP_OK: u8 = 0x80;
const RESP_DATA: u8 = 0x81;
const RESP_ERROR: u8 = 0xFF;

const MAX_MSG: usize = 4096;

// ── Server (nvme_driver, side B) ────────────────────────────────────
pub const Server = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Server {
        return .{ .chan = chan };
    }

    pub const Request = struct {
        tag: u8,
        payload: []const u8,
    };

    pub fn recv(self: *const Server, buf: []u8) ?Request {
        const len = (self.chan.receiveMessage(.B, buf) catch return null) orelse return null;
        if (len < 1) return null;
        return .{
            .tag = buf[0],
            .payload = buf[1..len],
        };
    }

    pub fn sendOk(self: *const Server) void {
        const bytes = [1]u8{RESP_OK};
        self.chan.sendMessage(.B, &bytes) catch {};
    }

    pub fn sendData(self: *const Server, data: []const u8) void {
        var buf: [1 + MAX_MSG]u8 = undefined;
        buf[0] = RESP_DATA;
        const copy_len = @min(data.len, MAX_MSG);
        @memcpy(buf[1..][0..copy_len], data[0..copy_len]);
        self.chan.sendMessage(.B, buf[0 .. 1 + copy_len]) catch {};
    }

    pub fn sendError(self: *const Server, msg: []const u8) void {
        var buf: [1 + 128]u8 = undefined;
        buf[0] = RESP_ERROR;
        const copy_len = @min(msg.len, 128);
        @memcpy(buf[1..][0..copy_len], msg[0..copy_len]);
        self.chan.sendMessage(.B, buf[0 .. 1 + copy_len]) catch {};
    }
};

// ── Client (terminal/apps, side A) ──────────────────────────────────
pub const Client = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Client {
        return .{ .chan = chan };
    }

    pub const Response = union(enum) {
        ok: void,
        data: []const u8,
        err: []const u8,
    };

    fn sendCmd(self: *const Client, tag: u8, payload: []const u8) void {
        var buf: [1 + MAX_MSG]u8 = undefined;
        buf[0] = tag;
        const copy_len = @min(payload.len, MAX_MSG);
        if (copy_len > 0) {
            @memcpy(buf[1..][0..copy_len], payload[0..copy_len]);
        }
        self.chan.sendMessage(.A, buf[0 .. 1 + copy_len]) catch {};
    }

    fn recvResponse(self: *const Client, buf: []u8) ?Response {
        var attempts: u32 = 0;
        while (attempts < 500_000) : (attempts += 1) {
            if (self.chan.receiveMessage(.A, buf) catch null) |len| {
                if (len < 1) return null;
                return switch (buf[0]) {
                    RESP_OK => .{ .ok = {} },
                    RESP_DATA => .{ .data = buf[1..len] },
                    RESP_ERROR => .{ .err = buf[1..len] },
                    else => null,
                };
            }
            syscall.thread_yield();
        }
        return null;
    }

    pub fn mkdir(self: *const Client, path: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_MKDIR, path);
        return self.recvResponse(resp_buf);
    }

    pub fn rmdir(self: *const Client, path: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_RMDIR, path);
        return self.recvResponse(resp_buf);
    }

    pub fn mkfile(self: *const Client, path: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_MKFILE, path);
        return self.recvResponse(resp_buf);
    }

    pub fn rmfile(self: *const Client, path: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_RMFILE, path);
        return self.recvResponse(resp_buf);
    }

    pub fn open(self: *const Client, path: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_OPEN, path);
        return self.recvResponse(resp_buf);
    }

    pub fn fsWrite(self: *const Client, data: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_WRITE, data);
        return self.recvResponse(resp_buf);
    }

    pub fn close(self: *const Client, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_CLOSE, &[0]u8{});
        return self.recvResponse(resp_buf);
    }

    pub fn ls(self: *const Client, path: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_LS, path);
        return self.recvResponse(resp_buf);
    }

    pub fn read(self: *const Client, path: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_READ, path);
        return self.recvResponse(resp_buf);
    }
};
