const lib = @import("lib");

const Channel = lib.channel.Channel;
const Protocol = lib.Protocol;

pub const protocol_id: Protocol = .usb_keyboard;

// ── Commands ─────────────────────────────────────────────────────────
// B→A (server → client)
const CMD_KEY_EVENT: u8 = 0x01;

const KEY_PAYLOAD = 3; // keycode(1) + state(1) + modifiers(1)

// ── Types ────────────────────────────────────────────────────────────
pub const Event = struct {
    keycode: u8,
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

// ── Server (usb_driver, side B) ─────────────────────────────────────
pub const Server = struct {
    pub fn send(chan: *Channel, event: Event) !void {
        const bytes = [1 + KEY_PAYLOAD]u8{
            CMD_KEY_EVENT,
            event.keycode,
            @intFromEnum(event.state),
            @bitCast(event.modifiers),
        };
        try chan.enqueue(.B, &bytes);
    }
};

// ── Client (app, side A) ────────────────────────────────────────────
pub const Client = struct {
    pub fn recv(chan: *Channel) ?Message {
        var buf: [1 + KEY_PAYLOAD]u8 = undefined;
        const len = chan.dequeue(.A, &buf) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            CMD_KEY_EVENT => if (len == 1 + KEY_PAYLOAD) Message{
                .key = .{
                    .keycode = buf[1],
                    .state = @enumFromInt(buf[2]),
                    .modifiers = @bitCast(buf[3]),
                },
            } else null,
            else => null,
        };
    }

    pub const Message = union(enum) {
        key: Event,
    };
};
