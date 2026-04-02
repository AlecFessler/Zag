const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

const Channel = channel.Channel;
const Protocol = lib.Protocol;

pub const protocol_id: Protocol = .mouse;
pub const SHM_SIZE: u64 = 4 * syscall.PAGE4K;

// ── Connection ──────────────────────────────────────────────────────

pub const ConnectError = error{
    ServerNotFound,
    ChannelFailed,
};

/// Discovers the mouse server (compositor) via broadcast table and connects.
/// Returns a Client ready to send mouse events.
pub fn connectToMouseServer(perm_view_addr: u64) ConnectError!Client {
    const handle = channel.findBroadcastHandle(perm_view_addr, .compositor) orelse
        return error.ServerNotFound;
    const conn = Channel.connectAsA(handle, .mouse, SHM_SIZE) orelse
        return error.ChannelFailed;
    return Client.init(conn.chan);
}

// ── Commands ─────────────────────────────────────────────────────────
// B→A (driver → consumer)
const CMD_MOUSE_EVENT: u8 = 0x01;

const MOUSE_PAYLOAD = 8; // buttons(2) + dx(2) + dy(2) + scroll_v(1) + scroll_h(1)
const MAX_WIRE = 9; // tag(1) + largest payload

// ── Button bits ─────────────────────────────────────────────────────
pub const BTN_LEFT: u16 = 1 << 0;
pub const BTN_RIGHT: u16 = 1 << 1;
pub const BTN_MIDDLE: u16 = 1 << 2;
pub const BTN_BACK: u16 = 1 << 3;
pub const BTN_FORWARD: u16 = 1 << 4;

// ── Types ────────────────────────────────────────────────────────────
pub const MouseEvent = struct {
    buttons: u16,
    dx: i16,
    dy: i16,
    scroll_v: i8,
    scroll_h: i8,
};

// ── Server (compositor, side B) ─────────────────────────────────────
pub const Server = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Server {
        return .{ .chan = chan };
    }

    pub fn recv(self: *const Server) ?Message {
        var buf: [MAX_WIRE]u8 = undefined;
        const len = (self.chan.receiveMessage(.B, &buf) catch return null) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            CMD_MOUSE_EVENT => if (len == 1 + MOUSE_PAYLOAD) Message{
                .mouse = .{
                    .buttons = @as(u16, buf[1]) | (@as(u16, buf[2]) << 8),
                    .dx = @bitCast(@as(u16, buf[3]) | (@as(u16, buf[4]) << 8)),
                    .dy = @bitCast(@as(u16, buf[5]) | (@as(u16, buf[6]) << 8)),
                    .scroll_v = @bitCast(buf[7]),
                    .scroll_h = @bitCast(buf[8]),
                },
            } else null,
            else => null,
        };
    }

    pub const Message = union(enum) {
        mouse: MouseEvent,
    };
};

// ── Client (usb_driver, side A) ─────────────────────────────────────
pub const Client = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Client {
        return .{ .chan = chan };
    }

    pub fn sendMouse(self: *const Client, event: MouseEvent) !void {
        const buttons: u16 = event.buttons;
        const dx: u16 = @bitCast(event.dx);
        const dy: u16 = @bitCast(event.dy);
        const bytes = [1 + MOUSE_PAYLOAD]u8{
            CMD_MOUSE_EVENT,
            @truncate(buttons),
            @truncate(buttons >> 8),
            @truncate(dx),
            @truncate(dx >> 8),
            @truncate(dy),
            @truncate(dy >> 8),
            @bitCast(event.scroll_v),
            @bitCast(event.scroll_h),
        };
        try self.chan.sendMessage(.A, &bytes);
    }
};
