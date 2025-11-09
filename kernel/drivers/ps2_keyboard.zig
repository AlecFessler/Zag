const std = @import("std");
const zag = @import("zag");

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

pub const CommandQueue = struct {
    queue: [QUEUE_SIZE]CommandByte = undefined,
    head: i16 = -1,
    tail: i16 = -1,

    const QUEUE_SIZE = 256;

    pub fn enqueue(self: *CommandQueue, byte: CommandByte) !void {
        if (self.head == -1) {
            self.head = 0;
            self.tail = 0;
            self.queue[0] = byte;
            return;
        }
        const next = (self.tail + 1) % QUEUE_SIZE;
        if (next == self.head) return error.QueueFull;
        self.tail = next;
        self.queue[self.tail] = byte;
    }

    pub fn dequeue(self: *CommandQueue) ?CommandByte {
        if (self.head == -1) return null;
        const byte = self.queue[self.head];
        if (self.head == self.tail) {
            self.head = -1;
            self.tail = -1;
            return byte;
        }
        self.head = (self.head + 1) % QUEUE_SIZE;
        return byte;
    }

    pub fn peek(self: *const CommandQueue) ?CommandByte {
        if (self.head == -1) return null;
        return self.queue[self.head];
    }
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

var cmdq: CommandQueue = .{
    .queue = undefined,
    .head = -1,
    .tail = -1,
};

pub fn sendCmd() !void {}
