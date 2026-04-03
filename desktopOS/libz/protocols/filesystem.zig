const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

const Channel = channel.Channel;
const Protocol = lib.Protocol;

pub const protocol_id: Protocol = .filesystem;
pub const SHM_SIZE: u64 = 16 * syscall.PAGE4K; // 64 KiB

// ── Commands (A→B, client → server) ─────────────────────────────────
const CMD_MKDIR: u8 = 0x01;
const CMD_RMDIR: u8 = 0x02;
const CMD_MKFILE: u8 = 0x03;
const CMD_RMFILE: u8 = 0x04;
const CMD_READ: u8 = 0x05;
const CMD_WRITE: u8 = 0x06;
const CMD_LS: u8 = 0x07;
const CMD_STAT: u8 = 0x08;
const CMD_RENAME: u8 = 0x09;
const CMD_TRUNCATE: u8 = 0x0A;

// ── Responses (B→A, server → client) ────────────────────────────────
const RESP_OK: u8 = 0x80;
const RESP_DATA: u8 = 0x81;
const RESP_STAT: u8 = 0x82;
const RESP_ERROR: u8 = 0xFF;

const MAX_MSG: usize = 4096;

// ── Connection ──────────────────────────────────────────────────────

pub const ConnectError = error{
    ServerNotFound,
    ChannelFailed,
};

pub fn connectToServer(perm_view_addr: u64) ConnectError!Client {
    const handle = channel.findBroadcastHandle(perm_view_addr, .filesystem) orelse
        return error.ServerNotFound;
    const conn = Channel.connectAsA(handle, .filesystem, SHM_SIZE) catch
        return error.ChannelFailed;
    return Client.init(conn.chan);
}

// ── Stat info ───────────────────────────────────────────────────────

pub const FileType = enum(u8) {
    file = 0,
    directory = 1,
};

pub const StatInfo = struct {
    size: u64,
    file_type: FileType,
    created: u64,
    modified: u64,
    accessed: u64,
};

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

    pub fn sendStat(self: *const Server, info: StatInfo) void {
        var buf: [34]u8 = undefined; // 1 tag + 33 payload
        buf[0] = RESP_STAT;
        writeU64(buf[1..], 0, info.size);
        buf[9] = @intFromEnum(info.file_type);
        writeU64(buf[1..], 9, info.created);
        writeU64(buf[1..], 17, info.modified);
        writeU64(buf[1..], 25, info.accessed);
        self.chan.sendMessage(.B, &buf) catch {};
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
        stat: StatInfo,
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
                    RESP_STAT => blk: {
                        if (len < 34) break :blk null;
                        break :blk .{ .stat = .{
                            .size = readU64(buf[1..], 0),
                            .file_type = @enumFromInt(buf[9]),
                            .created = readU64(buf[1..], 9),
                            .modified = readU64(buf[1..], 17),
                            .accessed = readU64(buf[1..], 25),
                        } };
                    },
                    RESP_ERROR => .{ .err = buf[1..len] },
                    else => null,
                };
            }
            syscall.thread_yield();
        }
        return null;
    }

    // Simple path commands
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

    pub fn ls(self: *const Client, path: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_LS, path);
        return self.recvResponse(resp_buf);
    }

    pub fn stat(self: *const Client, path: []const u8, resp_buf: []u8) ?Response {
        self.sendCmd(CMD_STAT, path);
        return self.recvResponse(resp_buf);
    }

    // READ: offset(u64) + size(u64) + path
    pub fn read(self: *const Client, path: []const u8, offset: u64, size: u64, resp_buf: []u8) ?Response {
        var buf: [1 + 16 + MAX_MSG]u8 = undefined;
        buf[0] = CMD_READ;
        writeU64(buf[1..], 0, offset);
        writeU64(buf[1..], 8, size);
        const path_len = @min(path.len, MAX_MSG);
        @memcpy(buf[17..][0..path_len], path[0..path_len]);
        self.chan.sendMessage(.A, buf[0 .. 17 + path_len]) catch {};
        return self.recvResponse(resp_buf);
    }

    // WRITE: offset(u64) + path_len(u16) + path + data
    pub fn write(self: *const Client, path: []const u8, offset: u64, data: []const u8, resp_buf: []u8) ?Response {
        var buf: [1 + 10 + MAX_MSG]u8 = undefined;
        buf[0] = CMD_WRITE;
        writeU64(buf[1..], 0, offset);
        const pl: u16 = @intCast(@min(path.len, MAX_MSG - data.len));
        buf[9] = @truncate(pl);
        buf[10] = @truncate(pl >> 8);
        @memcpy(buf[11..][0..pl], path[0..pl]);
        const data_len = @min(data.len, MAX_MSG - pl);
        @memcpy(buf[11 + pl ..][0..data_len], data[0..data_len]);
        self.chan.sendMessage(.A, buf[0 .. 11 + pl + data_len]) catch {};
        return self.recvResponse(resp_buf);
    }

    // RENAME: path1_len(u16) + path1 + path2
    pub fn rename(self: *const Client, src: []const u8, dst: []const u8, resp_buf: []u8) ?Response {
        var buf: [1 + 2 + MAX_MSG]u8 = undefined;
        buf[0] = CMD_RENAME;
        const sl: u16 = @intCast(@min(src.len, MAX_MSG - dst.len));
        buf[1] = @truncate(sl);
        buf[2] = @truncate(sl >> 8);
        @memcpy(buf[3..][0..sl], src[0..sl]);
        const dl = @min(dst.len, MAX_MSG - sl);
        @memcpy(buf[3 + sl ..][0..dl], dst[0..dl]);
        self.chan.sendMessage(.A, buf[0 .. 3 + sl + dl]) catch {};
        return self.recvResponse(resp_buf);
    }

    // TRUNCATE: size(u64) + path
    pub fn truncate(self: *const Client, path: []const u8, size: u64, resp_buf: []u8) ?Response {
        var buf: [1 + 8 + MAX_MSG]u8 = undefined;
        buf[0] = CMD_TRUNCATE;
        writeU64(buf[1..], 0, size);
        const path_len = @min(path.len, MAX_MSG);
        @memcpy(buf[9..][0..path_len], path[0..path_len]);
        self.chan.sendMessage(.A, buf[0 .. 9 + path_len]) catch {};
        return self.recvResponse(resp_buf);
    }
};

// ── Byte helpers ────────────────────────────────────────────────────

fn readU64(buf: []const u8, offset: usize) u64 {
    return @as(u64, buf[offset]) |
        (@as(u64, buf[offset + 1]) << 8) |
        (@as(u64, buf[offset + 2]) << 16) |
        (@as(u64, buf[offset + 3]) << 24) |
        (@as(u64, buf[offset + 4]) << 32) |
        (@as(u64, buf[offset + 5]) << 40) |
        (@as(u64, buf[offset + 6]) << 48) |
        (@as(u64, buf[offset + 7]) << 56);
}

fn writeU64(buf: []u8, offset: usize, val: u64) void {
    buf[offset] = @truncate(val);
    buf[offset + 1] = @truncate(val >> 8);
    buf[offset + 2] = @truncate(val >> 16);
    buf[offset + 3] = @truncate(val >> 24);
    buf[offset + 4] = @truncate(val >> 32);
    buf[offset + 5] = @truncate(val >> 40);
    buf[offset + 6] = @truncate(val >> 48);
    buf[offset + 7] = @truncate(val >> 56);
}
