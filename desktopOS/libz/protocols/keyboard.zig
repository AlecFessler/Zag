const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

const Channel = channel.Channel;
const Protocol = lib.Protocol;

pub const protocol_id: Protocol = .keyboard;
pub const SHM_SIZE: u64 = 4 * syscall.PAGE4K;

// ── Connection ──────────────────────────────────────────────────────

pub const ConnectError = error{
    ServerNotFound,
    ChannelFailed,
};

/// Discovers the keyboard server (USB HID driver) via broadcast table and connects.
/// Returns a Client ready to receive key events.
pub fn connectToServer(perm_view_addr: u64) ConnectError!Client {
    const handle = channel.findBroadcastHandle(perm_view_addr, .keyboard) orelse
        return error.ServerNotFound;
    const conn = Channel.connectAsA(handle, .keyboard, SHM_SIZE) catch
        return error.ChannelFailed;
    return Client.init(conn.chan);
}

// ── Commands ─────────────────────────────────────────────────────────
// B→A (driver → consumer)
const CMD_KEY_EVENT: u8 = 0x01;
// A→B (consumer → driver)
const CMD_SET_LEDS: u8 = 0x10;

const KEY_PAYLOAD = 4; // keycode(2) + state(1) + modifiers(1)
const LED_PAYLOAD = 1; // leds(1)
const MAX_WIRE = 5; // tag(1) + largest payload

// ── Types ────────────────────────────────────────────────────────────
pub const Event = struct {
    keycode: u16,
    state: State,
    modifiers: Modifiers,
};

pub const State = enum(u8) {
    released = 0,
    pressed = 1,
};

pub const Modifiers = packed struct(u8) {
    l_ctrl: bool = false,
    l_shift: bool = false,
    l_alt: bool = false,
    l_gui: bool = false,
    r_ctrl: bool = false,
    r_shift: bool = false,
    r_alt: bool = false,
    r_gui: bool = false,
};

pub const Leds = packed struct(u8) {
    num_lock: bool = false,
    caps_lock: bool = false,
    scroll_lock: bool = false,
    _reserved: u5 = 0,
};

// ── Client (consumer, side A) ───────────────────────────────────────
pub const Client = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Client {
        return .{ .chan = chan };
    }

    pub fn recv(self: *const Client) ?Message {
        var buf: [MAX_WIRE]u8 = undefined;
        const len = (self.chan.receiveMessage(.A, &buf) catch return null) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            CMD_KEY_EVENT => if (len == 1 + KEY_PAYLOAD) Message{
                .key = .{
                    .keycode = @as(u16, buf[1]) | (@as(u16, buf[2]) << 8),
                    .state = @enumFromInt(buf[3]),
                    .modifiers = @bitCast(buf[4]),
                },
            } else null,
            else => null,
        };
    }

    pub fn sendLeds(self: *const Client, leds: Leds) !void {
        const bytes = [1 + LED_PAYLOAD]u8{
            CMD_SET_LEDS,
            @bitCast(leds),
        };
        try self.chan.sendMessage(.A, &bytes);
    }

    pub const Message = union(enum) {
        key: Event,
    };
};

// ── Server (USB HID driver, side B) ─────────────────────────────────
pub const Server = struct {
    chan: *Channel,

    pub fn init(chan: *Channel) Server {
        return .{ .chan = chan };
    }

    pub fn send(self: *const Server, event: Event) !void {
        const keycode: u16 = event.keycode;
        const bytes = [1 + KEY_PAYLOAD]u8{
            CMD_KEY_EVENT,
            @truncate(keycode),
            @truncate(keycode >> 8),
            @intFromEnum(event.state),
            @bitCast(event.modifiers),
        };
        try self.chan.sendMessage(.B, &bytes);
    }

    pub fn recvLeds(self: *const Server) ?Leds {
        var buf: [1 + LED_PAYLOAD]u8 = undefined;
        const len = (self.chan.receiveMessage(.B, &buf) catch return null) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            CMD_SET_LEDS => if (len == 1 + LED_PAYLOAD) @as(Leds, @bitCast(buf[1])) else null,
            else => null,
        };
    }
};
