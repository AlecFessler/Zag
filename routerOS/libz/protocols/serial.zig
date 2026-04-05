const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

const Channel = channel.Channel;

pub const protocol_id = lib.Protocol.serial;
pub const SHM_SIZE: u64 = 4 * syscall.PAGE4K;

// ── Connection ──────────────────────────────────────────────────────

pub const ConnectError = error{
    ServerNotFound,
    ChannelFailed,
};

pub fn connectToServer(perm_view_addr: u64) ConnectError!Client {
    const handle = channel.findBroadcastHandle(perm_view_addr, .serial) orelse
        return error.ServerNotFound;
    const conn = Channel.connectAsA(handle, .serial, SHM_SIZE) catch
        return error.ChannelFailed;
    return Client.init(conn.chan);
}

// ── Client (side A) ─────────────────────────────────────���───────────

pub const Client = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Client {
        return .{ .chan = chan };
    }

    pub fn send(self: *const Client, data: []const u8) void {
        self.chan.sendMessage(.A, data) catch {};
    }

    pub fn recv(self: *const Client, buf: []u8) ?[]const u8 {
        const len = (self.chan.receiveMessage(.A, buf) catch return null) orelse return null;
        return buf[0..len];
    }

    pub fn waitForMessage(self: *const Client, timeout_ns: u64) void {
        self.chan.waitForMessage(.A, timeout_ns);
    }
};

// ── Server (side B) ─────────────────────────────────────────────────

pub const Server = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Server {
        return .{ .chan = chan };
    }

    pub fn send(self: *const Server, data: []const u8) void {
        self.chan.sendMessage(.B, data) catch {};
    }

    pub fn recv(self: *const Server, buf: []u8) ?[]const u8 {
        const len = (self.chan.receiveMessage(.B, buf) catch return null) orelse return null;
        return buf[0..len];
    }

    pub fn waitForMessage(self: *const Server, timeout_ns: u64) void {
        self.chan.waitForMessage(.B, timeout_ns);
    }
};
