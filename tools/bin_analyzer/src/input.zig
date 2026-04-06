const std = @import("std");
const ansi = @import("ansi.zig");

pub const Action = enum {
    quit,
    down,
    up,
    left,
    right,
    tab,
    half_page_down,
    half_page_up,
    goto_file,
    goto_def,
    go_back,
    word_forward,
    word_backward,
    line_start,
    line_end,
    none,
};

pub fn readInput(tty: std.fs.File) !Action {
    var buf: [1]u8 = undefined;
    const n = try tty.read(&buf);
    if (n == 0) return .quit;

    return switch (buf[0]) {
        'q', ansi.key_ctrl_c => .quit,
        'j' => .down,
        'k' => .up,
        'h' => .left,
        'l' => .right,
        ansi.key_tab => .tab,
        '/' => .goto_file,
        'w' => .word_forward,
        'b' => .word_backward,
        '0' => .line_start,
        '$' => .line_end,
        'g' => readGCommand(tty),
        ansi.key_ctrl_d => .half_page_down,
        ansi.key_ctrl_u => .half_page_up,
        else => .none,
    };
}

fn readGCommand(tty: std.fs.File) !Action {
    var buf: [1]u8 = undefined;
    const n = try tty.read(&buf);
    if (n == 0) return .none;
    return switch (buf[0]) {
        'd' => .goto_def,
        'b' => .go_back,
        else => .none,
    };
}
