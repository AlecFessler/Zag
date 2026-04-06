const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

const Channel = channel.Channel;

pub const protocol_id = lib.Protocol.http_server;
pub const SHM_SIZE: u64 = 4 * syscall.PAGE4K;

// ── A→B commands (http_server → router) ─────────────────────────────
pub const CMD_HTTP_RESPONSE: u8 = 0x11;
pub const CMD_STATE_QUERY: u8 = 0x12;
pub const CMD_MUTATION_REQUEST: u8 = 0x14;

// ── B→A responses (router → http_server) ────────────────────────────
pub const RESP_HTTP_REQUEST: u8 = 0x10;
pub const RESP_STATE_RESPONSE: u8 = 0x13;
pub const RESP_MUTATION_RESPONSE: u8 = 0x15;

// ── State query endpoint IDs ────────────────────────────────────────
pub const EP_STATUS: u8 = 0;
pub const EP_IFSTAT: u8 = 1;
pub const EP_ARP: u8 = 2;
pub const EP_NAT: u8 = 3;
pub const EP_LEASES: u8 = 4;
pub const EP_RULES: u8 = 5;

// ── Mutation types ──────────────────────────────────────────────────
pub const MUT_BLOCK: u8 = 0;
pub const MUT_ALLOW: u8 = 1;
pub const MUT_FORWARD: u8 = 2;
pub const MUT_UNFORWARD: u8 = 3;
pub const MUT_DNS: u8 = 4;
pub const MUT_TIMEZONE: u8 = 5;
pub const MUT_FORWARD_LEASED: u8 = 6;

// ── Types ───────────────────────────────────────────────────────────

pub const ServerMessage = union(enum) {
    http_request: []const u8,
    state_response: []const u8,
    mutation_response: []const u8,
};

pub const ClientMessage = union(enum) {
    http_response: []const u8,
    state_query: []const u8,
    mutation_request: []const u8,
};

// ── Client (side A — http_server) ───────────────────────────────────

pub const Client = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Client {
        return .{ .chan = chan };
    }

    pub fn sendHttpResponse(self: *const Client, msg: []const u8) void {
        self.chan.sendMessage(.A, msg) catch {};
    }

    pub fn sendStateQuery(self: *const Client, endpoint: u8) void {
        self.chan.sendMessage(.A, &[_]u8{ CMD_STATE_QUERY, endpoint }) catch {};
    }

    pub fn sendMutationRequest(self: *const Client, msg: []const u8) void {
        self.chan.sendMessage(.A, msg) catch {};
    }

    pub fn recv(self: *const Client, buf: []u8) ?ServerMessage {
        const len = (self.chan.receiveMessage(.A, buf) catch return null) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            RESP_HTTP_REQUEST => ServerMessage{ .http_request = buf[1..len] },
            RESP_STATE_RESPONSE => ServerMessage{ .state_response = buf[1..len] },
            RESP_MUTATION_RESPONSE => ServerMessage{ .mutation_response = buf[1..len] },
            else => null,
        };
    }

    pub fn recvRaw(self: *const Client, buf: []u8) ?[]const u8 {
        const len = (self.chan.receiveMessage(.A, buf) catch return null) orelse return null;
        if (len < 1) return null;
        return buf[0..len];
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

    pub fn sendHttpRequest(self: *const Server, raw_http: []const u8) void {
        var msg: [2048]u8 = undefined;
        const total = 1 + raw_http.len;
        if (total > msg.len) return;
        msg[0] = RESP_HTTP_REQUEST;
        @memcpy(msg[1..][0..raw_http.len], raw_http);
        self.chan.sendMessage(.B, msg[0..total]) catch {};
    }

    pub fn sendStateResponse(self: *const Server, json: []const u8) void {
        var msg: [4096]u8 = undefined;
        const total = 1 + json.len;
        if (total > msg.len) return;
        msg[0] = RESP_STATE_RESPONSE;
        @memcpy(msg[1..][0..json.len], json);
        self.chan.sendMessage(.B, msg[0..total]) catch {};
    }

    pub fn sendMutationResponse(self: *const Server, json: []const u8) void {
        var msg: [4096]u8 = undefined;
        const total = 1 + json.len;
        if (total > msg.len) return;
        msg[0] = RESP_MUTATION_RESPONSE;
        @memcpy(msg[1..][0..json.len], json);
        self.chan.sendMessage(.B, msg[0..total]) catch {};
    }

    pub fn waitForMessage(self: *const Server, timeout_ns: u64) void {
        self.chan.waitForMessage(.B, timeout_ns);
    }
};
