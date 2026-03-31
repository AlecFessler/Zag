const lib = @import("lib");

const Channel = lib.channel.Channel;
const Protocol = lib.Protocol;

pub const protocol_id: Protocol = .compositor;
pub const SHM_SIZE: u64 = 16 * 1024 * 1024;

// ── Commands ─────────────────────────────────────────────────────────
// B→A (server → client)
const CMD_RENDER_TARGET: u8 = 0x01;
const CMD_PANE_CREATED: u8 = 0x02;
const CMD_PANE_ACTIVATED: u8 = 0x03;
const CMD_WINDOW_RESIZED: u8 = 0x04;

// A→B (client → server) — tagged commands (small messages)
const CMD_REQUEST_NEW_PANE: u8 = 0x10;
const CMD_SLIDE_LEFT: u8 = 0x11;
const CMD_SLIDE_RIGHT: u8 = 0x12;
const CMD_SWITCH_PANE: u8 = 0x13;
const CMD_CLIENT_EXIT: u8 = 0x14;

// ── Types ────────────────────────────────────────────────────────────
pub const RenderTargetInfo = struct {
    width: u32,
    height: u32,
    stride: u32,
    format: u32, // 0 = BGRA
};

const RENDER_TARGET_PAYLOAD = 16;
const PANE_ID_PAYLOAD = 1;
const CMD_FRAME_THRESHOLD = 32; // messages > 32 bytes are frame data

// ── Server (compositor, side B) ─────────────────────────────────────
pub const Server = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Server {
        return .{ .chan = chan };
    }

    pub fn sendRenderTarget(self: *const Server, info: RenderTargetInfo) !void {
        var bytes: [1 + RENDER_TARGET_PAYLOAD]u8 = undefined;
        bytes[0] = CMD_RENDER_TARGET;
        @as(*align(1) u32, @ptrCast(bytes[1..5])).* = info.width;
        @as(*align(1) u32, @ptrCast(bytes[5..9])).* = info.height;
        @as(*align(1) u32, @ptrCast(bytes[9..13])).* = info.stride;
        @as(*align(1) u32, @ptrCast(bytes[13..17])).* = info.format;
        try self.chan.enqueue(.B, &bytes);
    }

    pub fn sendWindowResized(self: *const Server, info: RenderTargetInfo) !void {
        var bytes: [1 + RENDER_TARGET_PAYLOAD]u8 = undefined;
        bytes[0] = CMD_WINDOW_RESIZED;
        @as(*align(1) u32, @ptrCast(bytes[1..5])).* = info.width;
        @as(*align(1) u32, @ptrCast(bytes[5..9])).* = info.height;
        @as(*align(1) u32, @ptrCast(bytes[9..13])).* = info.stride;
        @as(*align(1) u32, @ptrCast(bytes[13..17])).* = info.format;
        try self.chan.enqueue(.B, &bytes);
    }

    pub fn sendPaneCreated(self: *const Server, pane_id: u8) !void {
        const bytes = [2]u8{ CMD_PANE_CREATED, pane_id };
        try self.chan.enqueue(.B, &bytes);
    }

    pub fn sendPaneActivated(self: *const Server, pane_id: u8) !void {
        const bytes = [2]u8{ CMD_PANE_ACTIVATED, pane_id };
        try self.chan.enqueue(.B, &bytes);
    }

    /// Receive a message from the client. Large messages (>32 bytes) are frame data,
    /// small messages are parsed as tagged commands.
    pub fn recvMessage(self: *const Server, frame_out: []u8) ?ServerMessage {
        const len = self.chan.dequeue(.B, frame_out) orelse return null;
        if (len > CMD_FRAME_THRESHOLD) {
            return .{ .frame = len };
        }
        if (len < 1) return null;
        return switch (frame_out[0]) {
            CMD_REQUEST_NEW_PANE => .request_new_pane,
            CMD_SLIDE_LEFT => .slide_left,
            CMD_SLIDE_RIGHT => .slide_right,
            CMD_SWITCH_PANE => if (len >= 2) ServerMessage{ .switch_pane = frame_out[1] } else null,
            CMD_CLIENT_EXIT => .client_exit,
            else => null,
        };
    }

    pub const ServerMessage = union(enum) {
        frame: u64,
        request_new_pane: void,
        slide_left: void,
        slide_right: void,
        switch_pane: u8,
        client_exit: void,
    };
};

// ── Client (app, side A) ────────────────────────────────────────────
pub const Client = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Client {
        return .{ .chan = chan };
    }

    pub fn sendFrame(self: *const Client, pixels: []const u8) !void {
        try self.chan.enqueue(.A, pixels);
    }

    pub fn requestNewPane(self: *const Client) !void {
        const bytes = [1]u8{CMD_REQUEST_NEW_PANE};
        try self.chan.enqueue(.A, &bytes);
    }

    pub fn slideLeft(self: *const Client) !void {
        const bytes = [1]u8{CMD_SLIDE_LEFT};
        try self.chan.enqueue(.A, &bytes);
    }

    pub fn slideRight(self: *const Client) !void {
        const bytes = [1]u8{CMD_SLIDE_RIGHT};
        try self.chan.enqueue(.A, &bytes);
    }

    pub fn switchPane(self: *const Client, pane_id: u8) !void {
        const bytes = [2]u8{ CMD_SWITCH_PANE, pane_id };
        try self.chan.enqueue(.A, &bytes);
    }

    pub fn sendExit(self: *const Client) !void {
        const bytes = [1]u8{CMD_CLIENT_EXIT};
        try self.chan.enqueue(.A, &bytes);
    }

    pub fn recv(self: *const Client) ?Message {
        var buf: [1 + RENDER_TARGET_PAYLOAD]u8 = undefined;
        const len = self.chan.dequeue(.A, &buf) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            CMD_RENDER_TARGET => parseRenderTarget(buf, len, .render_target),
            CMD_WINDOW_RESIZED => parseRenderTarget(buf, len, .window_resized),
            CMD_PANE_CREATED => if (len >= 2) Message{ .pane_created = buf[1] } else null,
            CMD_PANE_ACTIVATED => if (len >= 2) Message{ .pane_activated = buf[1] } else null,
            else => null,
        };
    }

    fn parseRenderTarget(buf: [1 + RENDER_TARGET_PAYLOAD]u8, len: u64, tag: enum { render_target, window_resized }) ?Message {
        if (len != 1 + RENDER_TARGET_PAYLOAD) return null;
        const info = RenderTargetInfo{
            .width = @as(*align(1) const u32, @ptrCast(buf[1..5])).*,
            .height = @as(*align(1) const u32, @ptrCast(buf[5..9])).*,
            .stride = @as(*align(1) const u32, @ptrCast(buf[9..13])).*,
            .format = @as(*align(1) const u32, @ptrCast(buf[13..17])).*,
        };
        return switch (tag) {
            .render_target => .{ .render_target = info },
            .window_resized => .{ .window_resized = info },
        };
    }

    pub const Message = union(enum) {
        render_target: RenderTargetInfo,
        window_resized: RenderTargetInfo,
        pane_created: u8,
        pane_activated: u8,
    };
};
