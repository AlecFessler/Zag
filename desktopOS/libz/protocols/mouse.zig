const lib = @import("lib");

const Channel = lib.channel.Channel;
const Protocol = lib.Protocol;

pub const protocol_id: Protocol = .input_control;

// ── Commands ─────────────────────────────────────────────────────────
// A→B (client → server)
const CMD_MOUSE_EVENT: u8 = 0x01;

const MOUSE_PAYLOAD = 5; // buttons(1) + dx(2) + dy(2)
const MAX_WIRE = 6; // tag(1) + largest payload

// ── Types ────────────────────────────────────────────────────────────
pub const Buttons = packed struct(u8) {
    left: bool = false,
    right: bool = false,
    middle: bool = false,
    _reserved: u5 = 0,
};

pub const MouseEvent = struct {
    buttons: Buttons,
    dx: i16,
    dy: i16,
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
                    .buttons = @bitCast(buf[1]),
                    .dx = @bitCast(@as(u16, buf[2]) | (@as(u16, buf[3]) << 8)),
                    .dy = @bitCast(@as(u16, buf[4]) | (@as(u16, buf[5]) << 8)),
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
        const dx: u16 = @bitCast(event.dx);
        const dy: u16 = @bitCast(event.dy);
        const bytes = [1 + MOUSE_PAYLOAD]u8{
            CMD_MOUSE_EVENT,
            @bitCast(event.buttons),
            @truncate(dx),
            @truncate(dx >> 8),
            @truncate(dy),
            @truncate(dy >> 8),
        };
        try self.chan.sendMessage(.A, &bytes);
    }
};
