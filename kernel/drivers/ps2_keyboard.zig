const std = @import("std");
const zag = @import("zag");

const cpu = zag.x86.Cpu;
const keyboard = zag.hal.keyboard;
const serial = zag.x86.Serial;

const ResponseByte = enum(u8) {
    key_detect_err_or_buffer_overflow_0 = 0x00,
    self_test_passed = 0xAA,
    echo = 0xEE,
    ack = 0xFA,
    self_test_failed_0 = 0xFC,
    self_test_failed_1 = 0xFD,
    resend = 0xFE,
    key_detect_err_or_buffer_overflow_1 = 0xFF,
};

pub const CommandByte = enum(u8) {
    set_leds = 0xED,
    echo = 0xEE,
    get_set_scs = 0xF0,
    id_keyboard = 0xF2,
    set_typematic_rate_delay = 0xF3,
    enable_scanning = 0xF4,
    disable_scanning = 0xF5,
    set_default_params = 0xF6,
    set_all_keys_typematic_autorepeat = 0xF7, // scs 3 only
    set_all_keys_make_release = 0xF8, // scs 3 only
    set_all_keys_make_only = 0xF9, // scs 3 only
    set_all_keys_typematic_autorepeat_make_release = 0xFA, // scs 3 only
    set_specific_key_typematic_autorepeat_only = 0xFB, // scs 3 only, takes key sc
    set_specific_key_make_release = 0xFC, // scs 3 only, takes key sc
    set_specific_key_make_only = 0xFD, // scs 3 only, takes key sc
    resend = 0xFE,
    reset_start_self_test = 0xFF,
};

const LedDataByte = packed struct(u8) {
    scroll_lock: bool,
    num_lock: bool,
    caps_lock: bool,
    _res: u5 = 0,
};

const GetSetScanCodeSetCmd = enum(u8) {
    get_scs = 0,
    set_scs_1 = 1,
    set_scs_2 = 2,
    set_scs_3 = 3,
};

const GetSetScanCodeSetRet = enum(u8) {
    got_scs_1 = 0x43,
    got_scs_2 = 0x41,
    got_scs_3 = 0x3F,
};

const TypematicRepeatRate = enum(u5) {
    hz30 = 0b00000,
    hz26_7 = 0b00001,
    hz24 = 0b00010,
    hz21_8 = 0b00011,
    hz20 = 0b00100,
    hz18_5 = 0b00101,
    hz17_1 = 0b00110,
    hz16 = 0b00111,
    hz15 = 0b01000,
    hz13_3 = 0b01001,
    hz12 = 0b01010,
    hz10_9 = 0b01011,
    hz10 = 0b01100,
    hz9_2 = 0b01101,
    hz8_6 = 0b01110,
    hz8 = 0b01111,
    hz7_5 = 0b10000,
    hz6_7 = 0b10001,
    hz6 = 0b10010,
    hz5_5 = 0b10011,
    hz5 = 0b10100,
    hz4_6 = 0b10101,
    hz4 = 0b10110,
    hz3_7 = 0b10111,
    hz3_3 = 0b11000,
    hz3 = 0b11001,
    hz2_7 = 0b11010,
    hz2_5 = 0b11011,
    hz2_3 = 0b11100,
    hz2_1 = 0b11101,
    hz2 = 0b11110,
};

const TypematicDelayBeforeRepeat = enum(u2) {
    ms250 = 0b00,
    ms500 = 0b01,
    ms750 = 0b10,
    ms1000 = 0b11,
};

const TypematicByte = packed struct(u8) {
    repeat_rate: TypematicRepeatRate,
    delay_before_repeat: TypematicDelayBeforeRepeat,
    _res: u1 = 0,
};

const ScanCodeSet1 = enum(u8) {
    escape_pressed = 0x01,
    _1_pressed = 0x02,
    _2_pressed = 0x03,
    _3_pressed = 0x04,
    _4_pressed = 0x05,
    _5_pressed = 0x06,
    _6_pressed = 0x07,
    _7_pressed = 0x08,
    _8_pressed = 0x09,
    _9_pressed = 0x0A,
    _0_pressed = 0x0B,
    minus_pressed = 0x0C,
    equals_pressed = 0x0D,
    backspace_pressed = 0x0E,
    tab_pressed = 0x0F,
    q_pressed = 0x10,
    w_pressed = 0x11,
    e_pressed = 0x12,
    r_pressed = 0x13,
    t_pressed = 0x14,
    y_pressed = 0x15,
    u_pressed = 0x16,
    i_pressed = 0x17,
    o_pressed = 0x18,
    p_pressed = 0x19,
    left_bracket_pressed = 0x1A,
    right_bracket_pressed = 0x1B,
    enter_pressed = 0x1C,
    left_control_pressed = 0x1D,
    a_pressed = 0x1E,
    s_pressed = 0x1F,
    d_pressed = 0x20,
    f_pressed = 0x21,
    g_pressed = 0x22,
    h_pressed = 0x23,
    j_pressed = 0x24,
    k_pressed = 0x25,
    l_pressed = 0x26,
    semicolon_pressed = 0x27,
    apostrophe_pressed = 0x28,
    grave_pressed = 0x29,
    left_shift_pressed = 0x2A,
    backslash_pressed = 0x2B,
    z_pressed = 0x2C,
    x_pressed = 0x2D,
    c_pressed = 0x2E,
    v_pressed = 0x2F,
    b_pressed = 0x30,
    n_pressed = 0x31,
    m_pressed = 0x32,
    comma_pressed = 0x33,
    period_pressed = 0x34,
    slash_pressed = 0x35,
    right_shift_pressed = 0x36,
    numpad_multiply_pressed = 0x37,
    left_alt_pressed = 0x38,
    space_pressed = 0x39,
    caps_lock_pressed = 0x3A,
    f1_pressed = 0x3B,
    f2_pressed = 0x3C,
    f3_pressed = 0x3D,
    f4_pressed = 0x3E,
    f5_pressed = 0x3F,
    f6_pressed = 0x40,
    f7_pressed = 0x41,
    f8_pressed = 0x42,
    f9_pressed = 0x43,
    f10_pressed = 0x44,
    num_lock_pressed = 0x45,
    scroll_lock_pressed = 0x46,
    numpad7_pressed = 0x47,
    numpad8_pressed = 0x48,
    numpad9_pressed = 0x49,
    numpad_subtract_pressed = 0x4A,
    numpad4_pressed = 0x4B,
    numpad5_pressed = 0x4C,
    numpad6_pressed = 0x4D,
    numpad_add_pressed = 0x4E,
    numpad1_pressed = 0x4F,
    numpad2_pressed = 0x50,
    numpad3_pressed = 0x51,
    numpad0_pressed = 0x52,
    numpad_decimal_pressed = 0x53,
    f11_pressed = 0x57,
    f12_pressed = 0x58,

    escape_released = 0x81,
    _1_released = 0x82,
    _2_released = 0x83,
    _3_released = 0x84,
    _4_released = 0x85,
    _5_released = 0x86,
    _6_released = 0x87,
    _7_released = 0x88,
    _8_released = 0x89,
    _9_released = 0x8A,
    _0_released = 0x8B,
    minus_released = 0x8C,
    equals_released = 0x8D,
    backspace_released = 0x8E,
    tab_released = 0x8F,
    q_released = 0x90,
    w_released = 0x91,
    e_released = 0x92,
    r_released = 0x93,
    t_released = 0x94,
    y_released = 0x95,
    u_released = 0x96,
    i_released = 0x97,
    o_released = 0x98,
    p_released = 0x99,
    left_bracket_released = 0x9A,
    right_bracket_released = 0x9B,
    enter_released = 0x9C,
    left_control_released = 0x9D,
    a_released = 0x9E,
    s_released = 0x9F,
    d_released = 0xA0,
    f_released = 0xA1,
    g_released = 0xA2,
    h_released = 0xA3,
    j_released = 0xA4,
    k_released = 0xA5,
    l_released = 0xA6,
    semicolon_released = 0xA7,
    apostrophe_released = 0xA8,
    grave_released = 0xA9,
    left_shift_released = 0xAA,
    backslash_released = 0xAB,
    z_released = 0xAC,
    x_released = 0xAD,
    c_released = 0xAE,
    v_released = 0xAF,
    b_released = 0xB0,
    n_released = 0xB1,
    m_released = 0xB2,
    comma_released = 0xB3,
    period_released = 0xB4,
    slash_released = 0xB5,
    right_shift_released = 0xB6,
    numpad_multiply_released = 0xB7,
    left_alt_released = 0xB8,
    space_released = 0xB9,
    caps_lock_released = 0xBA,
    f1_released = 0xBB,
    f2_released = 0xBC,
    f3_released = 0xBD,
    f4_released = 0xBE,
    f5_released = 0xBF,
    f6_released = 0xC0,
    f7_released = 0xC1,
    f8_released = 0xC2,
    f9_released = 0xC3,
    f10_released = 0xC4,
    num_lock_released = 0xC5,
    scroll_lock_released = 0xC6,
    numpad7_released = 0xC7,
    numpad8_released = 0xC8,
    numpad9_released = 0xC9,
    numpad_subtract_released = 0xCA,
    numpad4_released = 0xCB,
    numpad5_released = 0xCC,
    numpad6_released = 0xCD,
    numpad_add_released = 0xCE,
    numpad1_released = 0xCF,
    numpad2_released = 0xD0,
    numpad3_released = 0xD1,
    numpad0_released = 0xD2,
    numpad_decimal_released = 0xD3,
    f11_released = 0xD7,
    f12_released = 0xD8,
};

const ScanCodeSet2 = enum(u8) {
    f9_pressed = 0x01,
    f5_pressed = 0x03,
    f3_pressed = 0x04,
    f1_pressed = 0x05,
    f2_pressed = 0x06,
    f12_pressed = 0x07,
    f10_pressed = 0x09,
    f8_pressed = 0x0A,
    f6_pressed = 0x0B,
    f4_pressed = 0x0C,
    tab_pressed = 0x0D,
    grave_pressed = 0x0E,

    left_alt_pressed = 0x11,
    left_shift_pressed = 0x12,

    left_control_pressed = 0x14,
    q_pressed = 0x15,
    _1_pressed = 0x16,

    z_pressed = 0x1A,
    s_pressed = 0x1B,
    a_pressed = 0x1C,
    w_pressed = 0x1D,
    _2_pressed = 0x1E,

    c_pressed = 0x21,
    x_pressed = 0x22,
    d_pressed = 0x23,
    e_pressed = 0x24,
    _4_pressed = 0x25,
    _3_pressed = 0x26,

    space_pressed = 0x29,
    v_pressed = 0x2A,
    f_pressed = 0x2B,
    t_pressed = 0x2C,
    r_pressed = 0x2D,
    _5_pressed = 0x2E,

    n_pressed = 0x31,
    b_pressed = 0x32,
    h_pressed = 0x33,
    g_pressed = 0x34,
    y_pressed = 0x35,
    _6_pressed = 0x36,

    m_pressed = 0x3A,
    j_pressed = 0x3B,
    u_pressed = 0x3C,
    _7_pressed = 0x3D,
    _8_pressed = 0x3E,

    comma_pressed = 0x41,
    k_pressed = 0x42,
    i_pressed = 0x43,
    o_pressed = 0x44,
    _0_pressed = 0x45,
    _9_pressed = 0x46,

    period_pressed = 0x49,
    slash_pressed = 0x4A,
    l_pressed = 0x4B,
    semicolon_pressed = 0x4C,
    p_pressed = 0x4D,
    minus_pressed = 0x4E,

    apostrophe_pressed = 0x52,

    left_bracket_pressed = 0x54,
    equals_pressed = 0x55,

    caps_lock_pressed = 0x58,
    right_shift_pressed = 0x59,
    enter_pressed = 0x5A,
    right_bracket_pressed = 0x5B,
    backslash_pressed = 0x5D,

    backspace_pressed = 0x66,

    numpad1_pressed = 0x69,
    numpad4_pressed = 0x6B,
    numpad7_pressed = 0x6C,

    numpad0_pressed = 0x70,
    numpad_decimal_pressed = 0x71,
    numpad2_pressed = 0x72,
    numpad5_pressed = 0x73,
    numpad6_pressed = 0x74,
    numpad8_pressed = 0x75,
    escape_pressed = 0x76,
    num_lock_pressed = 0x77,
    f11_pressed = 0x78,
    numpad_add_pressed = 0x79,
    numpad3_pressed = 0x7A,
    numpad_subtract_pressed = 0x7B,
    numpad_multiply_pressed = 0x7C,
    numpad9_pressed = 0x7D,
    scroll_lock_pressed = 0x7E,

    f7_pressed = 0x83,

    prefix_e0 = 0xE0,
    prefix_f0 = 0xF0,
    prefix_e1 = 0xE1,
};

const ScanCodeSet3 = enum(u8) {
    a = 0x1C,
    b = 0x32,
    c = 0x21,
    d = 0x23,
    e = 0x24,
    f = 0x2B,
    g = 0x34,
    h = 0x33,
    i = 0x43,
    j = 0x3B,
    k = 0x42,
    l = 0x4B,
    m = 0x3A,
    n = 0x31,
    o = 0x44,
    p = 0x4D,
    q = 0x15,
    r = 0x2D,
    s = 0x1B,
    t = 0x2C,
    u = 0x3C,
    v = 0x2A,
    w = 0x1D,
    x = 0x22,
    y = 0x35,
    z = 0x1A,
};

pub const Config = struct {
    desired_scs: GetSetScanCodeSetCmd = .set_scs_2,
    typematic: TypematicByte = .{
        .repeat_rate = .hz30,
        .delay_before_repeat = .ms250,
    },
    leds: LedDataByte = .{
        .scroll_lock = false,
        .num_lock = false,
        .caps_lock = false,
    },
};

pub const ScanCodeSet = enum {
    scs1,
    scs2,
    scs3,
};

pub const InitError = error{
    self_test_failed,
    timed_out,
    unsupported_scan_code_set,
    controller_error,
};

pub const CmdError = error{
    timed_out,
    controller_busy,
    resend_limit_exceeded,
    unexpected_response,
    device_error,
    key_detect_or_buffer_overflow,
    line_fault,
};

pub const ScsError = CmdError || error{
    unsupported_scan_code_set,
};

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const CMD_PORT: u16 = 0x64;

const STATUS_OBF: u8 = 1 << 0;
const STATUS_IBF: u8 = 1 << 1;
const STATUS_TO: u8 = 1 << 6;
const STATUS_PAR: u8 = 1 << 7;

const MAX_SPINS: u64 = 50_000;
const MAX_RESENDS: u32 = 3;

var sc_e0: bool = false;
var sc_break: bool = false;
var sc_e1: bool = false;
var sc_e1_count: u3 = 0;

pub fn init(cfg: Config) !void {
    if (pollRawByte() != null) flushControllerOutputBuffer();

    try sendDeviceCommand(@intFromEnum(CommandByte.disable_scanning));
    try sendDeviceCommand(@intFromEnum(CommandByte.reset_start_self_test));

    if (!waitObFSet()) return error.timed_out;
    const first = cpu.inb(DATA_PORT);
    if (first != 0xAA and first != 0xFA) {}
    if (first == 0xFA) {
        if (!waitObFSet()) return error.timed_out;
        const st = status();
        const b = cpu.inb(DATA_PORT);
        if ((st & (STATUS_TO | STATUS_PAR)) != 0) return error.controller_error;
        if (b != 0xAA) return error.self_test_failed;
    } else if (first != 0xAA) {
        return error.self_test_failed;
    }

    try setScanCodeSet(cfg.desired_scs);
    try setTypematic(cfg.typematic);
    try setLeds(cfg.leds);
    try sendDeviceCommand(@intFromEnum(CommandByte.enable_scanning));
}

pub fn pollKeyEvent() ?keyboard.KeyAction {
    while (true) {
        const b_opt = pollRawByte() orelse return null;
        switch (b_opt) {
            0xE0 => {
                sc_e0 = true;
                continue;
            },
            0xE1 => {
                sc_e1 = true;
                sc_e1_count = 0;
                continue;
            },
            else => {},
        }
        if (sc_e1) {
            sc_e1_count += 1;
            if (sc_e1_count < 7) continue;
            sc_e1 = false;
            sc_e1_count = 0;
            sc_e0 = false;
            continue;
        }
        const code = b_opt;
        const is_e0 = sc_e0;
        sc_e0 = false;

        const k = keyboardFromSet1(code, is_e0) orelse continue;
        return k;
    }
}
pub fn setLeds(byte: LedDataByte) CmdError!void {
    try sendDeviceCommand(@intFromEnum(CommandByte.set_leds));
    try sendDeviceData(@bitCast(byte));
}

pub fn setTypematic(byte: TypematicByte) CmdError!void {
    try sendDeviceCommand(@intFromEnum(CommandByte.set_typematic_rate_delay));
    try sendDeviceData(@bitCast(byte));
}

fn status() u8 {
    return cpu.inb(STATUS_PORT);
}

fn waitIbFClear() bool {
    var i: u64 = 0;
    while (i < MAX_SPINS) : (i += 1) {
        if ((status() & STATUS_IBF) == 0) return true;
    }
    return false;
}

fn waitObFSet() bool {
    var i: u64 = 0;
    while (i < MAX_SPINS) : (i += 1) {
        if ((status() & STATUS_OBF) != 0) return true;
    }
    return false;
}

fn readDataChecked() CmdError!u8 {
    if (!waitObFSet()) return error.timed_out;
    const st = status();
    const b = cpu.inb(DATA_PORT);
    if ((st & STATUS_TO) != 0) return error.line_fault;
    if ((st & STATUS_PAR) != 0) return error.line_fault;
    return b;
}

fn writeData(b: u8) CmdError!void {
    if (!waitIbFClear()) return error.controller_busy;
    cpu.outb(b, DATA_PORT);
}

fn writeCommand(b: u8) CmdError!void {
    if (!waitIbFClear()) return error.controller_busy;
    cpu.outb(b, CMD_PORT);
}

fn sendDeviceCommand(cmd: u8) CmdError!void {
    var tries: u32 = 0;
    while (tries <= MAX_RESENDS) : (tries += 1) {
        try writeData(cmd);
        const r = try readDataChecked();
        if (r == 0xFA) return;
        if (r == 0xFE) continue;
        if (r == 0xFC or r == 0xFD) return error.device_error;
        if (r == 0x00 or r == 0xFF) return error.key_detect_or_buffer_overflow;
        return error.unexpected_response;
    }
    return error.resend_limit_exceeded;
}

fn sendDeviceData(data: u8) CmdError!void {
    var tries: u32 = 0;
    while (tries <= MAX_RESENDS) : (tries += 1) {
        try writeData(data);
        const r = try readDataChecked();
        if (r == 0xFA) return;
        if (r == 0xFE) continue;
        if (r == 0xFC or r == 0xFD) return error.device_error;
        if (r == 0x00 or r == 0xFF) return error.key_detect_or_buffer_overflow;
        return error.unexpected_response;
    }
    return error.resend_limit_exceeded;
}

fn pollRawByte() ?u8 {
    const st = status();
    if ((st & STATUS_OBF) == 0) return null;
    const b = cpu.inb(DATA_PORT);
    if ((st & (STATUS_TO | STATUS_PAR)) != 0) return null;
    return b;
}

fn getScanCodeSet() CmdError!ScanCodeSet {
    try sendDeviceCommand(@intFromEnum(CommandByte.get_set_scs));
    try sendDeviceData(@intFromEnum(GetSetScanCodeSetCmd.get_scs));
    const resp = try readDataChecked();
    return switch (resp) {
        0x41 => .scs2,
        0x43 => .scs1,
        0x3F => .scs3,
        else => error.unexpected_response,
    };
}

fn setScanCodeSet(byte: GetSetScanCodeSetCmd) ScsError!void {
    try sendDeviceCommand(@intFromEnum(CommandByte.get_set_scs));
    try sendDeviceData(@intFromEnum(byte));
    const verified = getScanCodeSet() catch return error.timed_out;
    const want: ScanCodeSet = switch (byte) {
        .set_scs_1 => .scs1,
        .set_scs_2 => .scs2,
        .set_scs_3 => .scs3,
        .get_scs => .scs2,
    };
    if (verified != want) return error.unsupported_scan_code_set;
}

fn flushControllerOutputBuffer() void {
    var i: u64 = 0;
    while (i < 256 and (status() & STATUS_OBF) != 0) : (i += 1) {
        _ = cpu.inb(DATA_PORT);
    }
}

fn isDataReady() bool {
    return (status() & STATUS_OBF) != 0;
}

fn keyboardFromSet2(code: u8, is_e0: bool, is_break: bool) ?keyboard.KeyAction {
    const action: keyboard.KeyAction.Action = if (is_break) .release else .press;

    const key: ?keyboard.Key = if (!is_e0) switch (code) {
        0x76 => .escape,

        0x05 => .f1,
        0x06 => .f2,
        0x04 => .f3,
        0x0C => .f4,
        0x03 => .f5,
        0x0B => .f6,
        0x83 => .f7,
        0x0A => .f8,
        0x01 => .f9,
        0x09 => .f10,
        0x78 => .f11,
        0x07 => .f12,

        0x58 => .caps_lock,
        0x12 => .left_shift,
        0x59 => .right_shift,
        0x14 => .left_ctrl,
        0x11 => .left_alt,

        0x0D => .tab,
        0x29 => .space,
        0x5A => .enter,
        0x66 => .backspace,

        0x15 => .q,
        0x1D => .w,
        0x24 => .e,
        0x2D => .r,
        0x2C => .t,
        0x35 => .y,
        0x3C => .u,
        0x43 => .i,
        0x44 => .o,
        0x4D => .p,

        0x1C => .a,
        0x1B => .s,
        0x23 => .d,
        0x2B => .f,
        0x34 => .g,
        0x33 => .h,
        0x3B => .j,
        0x42 => .k,
        0x4B => .l,
        0x4C => .semicolon,
        0x52 => .apostrophe,

        0x1A => .z,
        0x22 => .x,
        0x21 => .c,
        0x2A => .v,
        0x32 => .b,
        0x31 => .n,
        0x3A => .m,
        0x41 => .comma,
        0x49 => .period,
        0x4A => .slash,

        0x0E => .grave,
        0x16 => ._1,
        0x1E => ._2,
        0x26 => ._3,
        0x25 => ._4,
        0x2E => ._5,
        0x36 => ._6,
        0x3D => ._7,
        0x3E => ._8,
        0x46 => ._9,
        0x45 => ._0,
        0x4E => .minus,
        0x55 => .equals,
        0x54 => .left_bracket,
        0x5B => .right_bracket,
        0x5D => .backslash,

        0x77 => .num_lock,
        0x7C => .numpad_multiply,
        0x7B => .numpad_subtract,
        0x79 => .numpad_add,
        0x70 => .numpad0,
        0x69 => .numpad1,
        0x72 => .numpad2,
        0x7A => .numpad3,
        0x6B => .numpad4,
        0x73 => .numpad5,
        0x74 => .numpad6,
        0x6C => .numpad7,
        0x75 => .numpad8,
        0x7D => .numpad9,
        0x71 => .numpad_decimal,

        0x7E => .scroll_lock,

        else => null,
    } else switch (code) {
        0x11 => .right_alt,
        0x14 => .right_ctrl,

        0x1F => .left_meta,
        0x27 => .right_meta,
        0x2F => .menu,

        0x75 => .arrow_up,
        0x72 => .arrow_down,
        0x6B => .arrow_left,
        0x74 => .arrow_right,

        0x70 => .insert,
        0x71 => .delete,
        0x6C => .home,
        0x69 => .end,
        0x7D => .page_up,
        0x7A => .page_down,

        0x4A => .numpad_divide,
        0x5A => .numpad_enter,

        else => null,
    };

    if (key) |k| {
        var ascii: ?keyboard.Ascii = null;
        var uni: ?keyboard.Unicode = null;

        switch (k) {
            .a => {
                ascii = .a;
                uni = .a;
            },
            .b => {
                ascii = .b;
                uni = .b;
            },
            .c => {
                ascii = .c;
                uni = .c;
            },
            .d => {
                ascii = .d;
                uni = .d;
            },
            .e => {
                ascii = .e;
                uni = .e;
            },
            .f => {
                ascii = .f;
                uni = .f;
            },
            .g => {
                ascii = .g;
                uni = .g;
            },
            .h => {
                ascii = .h;
                uni = .h;
            },
            .i => {
                ascii = .i;
                uni = .i;
            },
            .j => {
                ascii = .j;
                uni = .j;
            },
            .k => {
                ascii = .k;
                uni = .k;
            },
            .l => {
                ascii = .l;
                uni = .l;
            },
            .m => {
                ascii = .m;
                uni = .m;
            },
            .n => {
                ascii = .n;
                uni = .n;
            },
            .o => {
                ascii = .o;
                uni = .o;
            },
            .p => {
                ascii = .p;
                uni = .p;
            },
            .q => {
                ascii = .q;
                uni = .q;
            },
            .r => {
                ascii = .r;
                uni = .r;
            },
            .s => {
                ascii = .s;
                uni = .s;
            },
            .t => {
                ascii = .t;
                uni = .t;
            },
            .u => {
                ascii = .u;
                uni = .u;
            },
            .v => {
                ascii = .v;
                uni = .v;
            },
            .w => {
                ascii = .w;
                uni = .w;
            },
            .x => {
                ascii = .x;
                uni = .x;
            },
            .y => {
                ascii = .y;
                uni = .y;
            },
            .z => {
                ascii = .z;
                uni = .z;
            },

            ._0 => {
                ascii = ._0;
                uni = ._0;
            },
            ._1 => {
                ascii = ._1;
                uni = ._1;
            },
            ._2 => {
                ascii = ._2;
                uni = ._2;
            },
            ._3 => {
                ascii = ._3;
                uni = ._3;
            },
            ._4 => {
                ascii = ._4;
                uni = ._4;
            },
            ._5 => {
                ascii = ._5;
                uni = ._5;
            },
            ._6 => {
                ascii = ._6;
                uni = ._6;
            },
            ._7 => {
                ascii = ._7;
                uni = ._7;
            },
            ._8 => {
                ascii = ._8;
                uni = ._8;
            },
            ._9 => {
                ascii = ._9;
                uni = ._9;
            },

            .space => {
                ascii = .space;
                uni = .space;
            },
            .tab => {
                ascii = .tab;
                uni = .tab;
            },
            .enter => {
                ascii = .enter;
                uni = .enter;
            },
            .backspace => {
                ascii = .backspace;
                uni = .backspace;
            },

            .minus => {
                ascii = .minus;
                uni = .minus;
            },
            .equals => {
                ascii = .equals;
                uni = .equals;
            },
            .left_bracket => {
                ascii = .left_bracket;
                uni = .left_bracket;
            },
            .right_bracket => {
                ascii = .right_bracket;
                uni = .right_bracket;
            },
            .backslash => {
                ascii = .backslash;
                uni = .backslash;
            },
            .semicolon => {
                ascii = .semicolon;
                uni = .semicolon;
            },
            .apostrophe => {
                ascii = .apostrophe;
                uni = .apostrophe;
            },
            .grave => {
                ascii = .grave;
                uni = .grave;
            },
            .comma => {
                ascii = .comma;
                uni = .comma;
            },
            .period => {
                ascii = .period;
                uni = .period;
            },
            .slash => {
                ascii = .slash;
                uni = .slash;
            },

            .numpad0 => {
                ascii = ._0;
                uni = ._0;
            },
            .numpad1 => {
                ascii = ._1;
                uni = ._1;
            },
            .numpad2 => {
                ascii = ._2;
                uni = ._2;
            },
            .numpad3 => {
                ascii = ._3;
                uni = ._3;
            },
            .numpad4 => {
                ascii = ._4;
                uni = ._4;
            },
            .numpad5 => {
                ascii = ._5;
                uni = ._5;
            },
            .numpad6 => {
                ascii = ._6;
                uni = ._6;
            },
            .numpad7 => {
                ascii = ._7;
                uni = ._7;
            },
            .numpad8 => {
                ascii = ._8;
                uni = ._8;
            },
            .numpad9 => {
                ascii = ._9;
                uni = ._9;
            },
            .numpad_enter => {
                ascii = .enter;
                uni = .enter;
            },

            else => {},
        }

        return .{
            .key = k,
            .unicode = uni,
            .ascii = ascii,
            .action = action,
        };
    }

    return null;
}

fn keyboardFromSet1(code: u8, is_e0: bool) ?keyboard.KeyAction {
    const is_break = (code & 0x80) != 0;
    const make_code = code & 0x7F;

    const action: keyboard.KeyAction.Action = if (is_break) .release else .press;

    const key: ?keyboard.Key = if (!is_e0) switch (make_code) {
        0x01 => .escape,

        0x3B => .f1,
        0x3C => .f2,
        0x3D => .f3,
        0x3E => .f4,
        0x3F => .f5,
        0x40 => .f6,
        0x41 => .f7,
        0x42 => .f8,
        0x43 => .f9,
        0x44 => .f10,
        0x57 => .f11,
        0x58 => .f12,

        0x3A => .caps_lock,
        0x2A => .left_shift,
        0x36 => .right_shift,
        0x1D => .left_ctrl,
        0x38 => .left_alt,

        0x0F => .tab,
        0x39 => .space,
        0x1C => .enter,
        0x0E => .backspace,

        0x10 => .q,
        0x11 => .w,
        0x12 => .e,
        0x13 => .r,
        0x14 => .t,
        0x15 => .y,
        0x16 => .u,
        0x17 => .i,
        0x18 => .o,
        0x19 => .p,

        0x1E => .a,
        0x1F => .s,
        0x20 => .d,
        0x21 => .f,
        0x22 => .g,
        0x23 => .h,
        0x24 => .j,
        0x25 => .k,
        0x26 => .l,
        0x27 => .semicolon,
        0x28 => .apostrophe,

        0x2C => .z,
        0x2D => .x,
        0x2E => .c,
        0x2F => .v,
        0x30 => .b,
        0x31 => .n,
        0x32 => .m,
        0x33 => .comma,
        0x34 => .period,
        0x35 => .slash,

        0x29 => .grave,
        0x02 => ._1,
        0x03 => ._2,
        0x04 => ._3,
        0x05 => ._4,
        0x06 => ._5,
        0x07 => ._6,
        0x08 => ._7,
        0x09 => ._8,
        0x0A => ._9,
        0x0B => ._0,
        0x0C => .minus,
        0x0D => .equals,
        0x1A => .left_bracket,
        0x1B => .right_bracket,
        0x2B => .backslash,

        0x45 => .num_lock,
        0x37 => .numpad_multiply,
        0x4A => .numpad_subtract,
        0x4E => .numpad_add,
        0x52 => .numpad0,
        0x4F => .numpad1,
        0x50 => .numpad2,
        0x51 => .numpad3,
        0x4B => .numpad4,
        0x4C => .numpad5,
        0x4D => .numpad6,
        0x47 => .numpad7,
        0x48 => .numpad8,
        0x49 => .numpad9,
        0x53 => .numpad_decimal,

        0x46 => .scroll_lock,

        else => null,
    } else switch (make_code) {
        0x1D => .right_ctrl,
        0x38 => .right_alt,

        0x5B => .left_meta,
        0x5C => .right_meta,
        0x5D => .menu,

        0x48 => .arrow_up,
        0x50 => .arrow_down,
        0x4B => .arrow_left,
        0x4D => .arrow_right,

        0x52 => .insert,
        0x53 => .delete,
        0x47 => .home,
        0x4F => .end,
        0x49 => .page_up,
        0x51 => .page_down,

        0x35 => .numpad_divide,
        0x1C => .numpad_enter,

        else => null,
    };

    if (key) |k| {
        var ascii: ?keyboard.Ascii = null;
        var uni: ?keyboard.Unicode = null;

        switch (k) {
            .a => {
                ascii = .a;
                uni = .a;
            },
            .b => {
                ascii = .b;
                uni = .b;
            },
            .c => {
                ascii = .c;
                uni = .c;
            },
            .d => {
                ascii = .d;
                uni = .d;
            },
            .e => {
                ascii = .e;
                uni = .e;
            },
            .f => {
                ascii = .f;
                uni = .f;
            },
            .g => {
                ascii = .g;
                uni = .g;
            },
            .h => {
                ascii = .h;
                uni = .h;
            },
            .i => {
                ascii = .i;
                uni = .i;
            },
            .j => {
                ascii = .j;
                uni = .j;
            },
            .k => {
                ascii = .k;
                uni = .k;
            },
            .l => {
                ascii = .l;
                uni = .l;
            },
            .m => {
                ascii = .m;
                uni = .m;
            },
            .n => {
                ascii = .n;
                uni = .n;
            },
            .o => {
                ascii = .o;
                uni = .o;
            },
            .p => {
                ascii = .p;
                uni = .p;
            },
            .q => {
                ascii = .q;
                uni = .q;
            },
            .r => {
                ascii = .r;
                uni = .r;
            },
            .s => {
                ascii = .s;
                uni = .s;
            },
            .t => {
                ascii = .t;
                uni = .t;
            },
            .u => {
                ascii = .u;
                uni = .u;
            },
            .v => {
                ascii = .v;
                uni = .v;
            },
            .w => {
                ascii = .w;
                uni = .w;
            },
            .x => {
                ascii = .x;
                uni = .x;
            },
            .y => {
                ascii = .y;
                uni = .y;
            },
            .z => {
                ascii = .z;
                uni = .z;
            },

            ._0 => {
                ascii = ._0;
                uni = ._0;
            },
            ._1 => {
                ascii = ._1;
                uni = ._1;
            },
            ._2 => {
                ascii = ._2;
                uni = ._2;
            },
            ._3 => {
                ascii = ._3;
                uni = ._3;
            },
            ._4 => {
                ascii = ._4;
                uni = ._4;
            },
            ._5 => {
                ascii = ._5;
                uni = ._5;
            },
            ._6 => {
                ascii = ._6;
                uni = ._6;
            },
            ._7 => {
                ascii = ._7;
                uni = ._7;
            },
            ._8 => {
                ascii = ._8;
                uni = ._8;
            },
            ._9 => {
                ascii = ._9;
                uni = ._9;
            },

            .space => {
                ascii = .space;
                uni = .space;
            },
            .tab => {
                ascii = .tab;
                uni = .tab;
            },
            .enter => {
                ascii = .enter;
                uni = .enter;
            },
            .backspace => {
                ascii = .backspace;
                uni = .backspace;
            },

            .minus => {
                ascii = .minus;
                uni = .minus;
            },
            .equals => {
                ascii = .equals;
                uni = .equals;
            },
            .left_bracket => {
                ascii = .left_bracket;
                uni = .left_bracket;
            },
            .right_bracket => {
                ascii = .right_bracket;
                uni = .right_bracket;
            },
            .backslash => {
                ascii = .backslash;
                uni = .backslash;
            },
            .semicolon => {
                ascii = .semicolon;
                uni = .semicolon;
            },
            .apostrophe => {
                ascii = .apostrophe;
                uni = .apostrophe;
            },
            .grave => {
                ascii = .grave;
                uni = .grave;
            },
            .comma => {
                ascii = .comma;
                uni = .comma;
            },
            .period => {
                ascii = .period;
                uni = .period;
            },
            .slash => {
                ascii = .slash;
                uni = .slash;
            },

            .numpad0 => {
                ascii = ._0;
                uni = ._0;
            },
            .numpad1 => {
                ascii = ._1;
                uni = ._1;
            },
            .numpad2 => {
                ascii = ._2;
                uni = ._2;
            },
            .numpad3 => {
                ascii = ._3;
                uni = ._3;
            },
            .numpad4 => {
                ascii = ._4;
                uni = ._4;
            },
            .numpad5 => {
                ascii = ._5;
                uni = ._5;
            },
            .numpad6 => {
                ascii = ._6;
                uni = ._6;
            },
            .numpad7 => {
                ascii = ._7;
                uni = ._7;
            },
            .numpad8 => {
                ascii = ._8;
                uni = ._8;
            },
            .numpad9 => {
                ascii = ._9;
                uni = ._9;
            },
            .numpad_enter => {
                ascii = .enter;
                uni = .enter;
            },

            else => {},
        }

        return .{
            .key = k,
            .unicode = uni,
            .ascii = ascii,
            .action = action,
        };
    }

    return null;
}
