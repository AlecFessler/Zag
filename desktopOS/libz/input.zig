/// Input event protocol for USB HID devices.
/// All events are fixed 8-byte little-endian messages sent over data channels.

pub const EVENT_SIZE = 8;

pub const Tag = struct {
    pub const KEYBOARD: u8 = 0x01;
    pub const MOUSE: u8 = 0x02;
};

pub const KeyState = struct {
    pub const RELEASED: u8 = 0;
    pub const PRESSED: u8 = 1;
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

    pub fn bits(self: Modifiers) u8 {
        return @bitCast(self);
    }
};

pub const MouseButtons = packed struct(u8) {
    left: bool = false,
    right: bool = false,
    middle: bool = false,
    _reserved: u5 = 0,

    pub fn bits(self: MouseButtons) u8 {
        return @bitCast(self);
    }
};

pub const KeyboardEvent = struct {
    keycode: u8,
    state: u8,
    modifiers: u8,
};

pub const MouseEvent = struct {
    buttons: u8,
    dx: i16,
    dy: i16,
};

pub fn encodeKeyboard(ev: KeyboardEvent) [EVENT_SIZE]u8 {
    return .{
        Tag.KEYBOARD,
        ev.keycode,
        ev.state,
        ev.modifiers,
        0, 0, 0, 0,
    };
}

pub fn encodeMouse(ev: MouseEvent) [EVENT_SIZE]u8 {
    const dx: u16 = @bitCast(ev.dx);
    const dy: u16 = @bitCast(ev.dy);
    return .{
        Tag.MOUSE,
        ev.buttons,
        @truncate(dx),
        @truncate(dx >> 8),
        @truncate(dy),
        @truncate(dy >> 8),
        0, 0,
    };
}

pub fn decodeTag(buf: []const u8) ?u8 {
    if (buf.len < EVENT_SIZE) return null;
    return buf[0];
}

pub fn decodeKeyboard(buf: []const u8) ?KeyboardEvent {
    if (buf.len < EVENT_SIZE or buf[0] != Tag.KEYBOARD) return null;
    return .{
        .keycode = buf[1],
        .state = buf[2],
        .modifiers = buf[3],
    };
}

pub fn decodeMouse(buf: []const u8) ?MouseEvent {
    if (buf.len < EVENT_SIZE or buf[0] != Tag.MOUSE) return null;
    return .{
        .buttons = buf[1],
        .dx = @bitCast(@as(u16, buf[2]) | (@as(u16, buf[3]) << 8)),
        .dy = @bitCast(@as(u16, buf[4]) | (@as(u16, buf[5]) << 8)),
    };
}
