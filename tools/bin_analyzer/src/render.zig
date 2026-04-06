const std = @import("std");
const ansi = @import("ansi.zig");
const syntax = @import("syntax.zig");
const disasm = @import("disasm.zig");

const Allocator = std.mem.Allocator;
const SyntaxColor = syntax.SyntaxColor;

pub const Pane = enum { source, disasm };

pub const View = struct {
    allocator: Allocator,
    tty: std.fs.File,
    term_w: u16,
    term_h: u16,

    // Source state
    current_file: ?[]const u8,
    current_file_lines: ?[][]const u8,
    src_cursor: usize,
    src_col: usize,
    src_scroll: usize,
    src_hscroll: usize,
    highlighted_source: *std.AutoHashMap(u32, void),

    // Disasm state
    disasm_lines: []disasm.DisasmLine,
    disasm_cursor: usize,
    disasm_col: usize,
    disasm_scroll: usize,
    disasm_hscroll: usize,
    highlighted_disasm: *std.AutoHashMap(usize, void),

    active_pane: Pane,
};

pub fn render(v: *View) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(v.allocator);
    const w = buf.writer(v.allocator);

    try w.writeAll(ansi.cursor_home);

    const height: usize = @as(usize, v.term_h) -| 2;
    const total_w: usize = @as(usize, v.term_w);
    const left_w = total_w / 2 -| 1;
    const right_w = total_w -| left_w -| 1;

    if (v.active_pane == .source) {
        ensureScroll(&v.src_scroll, v.src_cursor, height);
    } else {
        ensureScroll(&v.disasm_scroll, v.disasm_cursor, height);
    }

    for (0..height) |row| {
        const src_line_idx = v.src_scroll + row;
        try renderSourceLine(w, v, src_line_idx, left_w);

        try w.writeAll(ansi.fg_dark_gray ++ ansi.vertical_bar ++ ansi.reset);

        const disasm_line_idx = v.disasm_scroll + row;
        try renderDisasmLine(w, v, disasm_line_idx, right_w);

        try w.writeAll(ansi.clear_to_eol ++ "\n");
    }

    try w.writeAll(ansi.style_status);
    try renderStatusBar(w, v, total_w);
    try w.writeAll(ansi.reset ++ ansi.clear_to_eol);

    try v.tty.writeAll(buf.items);
}

pub fn renderPrompt(
    allocator: Allocator,
    tty: std.fs.File,
    term_w: u16,
    term_h: u16,
    prompt: []const u8,
    input_text: []const u8,
) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);

    const total_w: usize = @as(usize, term_w);
    const status_row = term_h -| 1;
    try w.print("\x1b[{d};1H" ++ ansi.reverse_video ++ "{s}", .{ status_row, prompt });
    try w.writeAll(input_text);
    const written = prompt.len + input_text.len;
    if (written < total_w) try padSpaces(w, total_w - written);
    try w.writeAll(ansi.reset);
    try tty.writeAll(buf.items);
}

pub fn ensureScroll(scroll: *usize, cursor: usize, visible: usize) void {
    if (visible == 0) return;
    const margin = @min(3, visible / 4);
    if (cursor < scroll.* + margin) {
        scroll.* = cursor -| margin;
    } else if (cursor + margin >= scroll.* + visible) {
        scroll.* = (cursor + margin + 1) -| visible;
    }
}

pub fn autoScroll(scroll: *usize, target: usize, visible_height: u16) void {
    const h = @as(usize, visible_height);
    if (h == 0) return;
    scroll.* = target -| (h / 2);
}

pub fn padSpaces(w: anytype, count: usize) !void {
    const spaces = "                                                                                ";
    var remaining = count;
    while (remaining > 0) {
        const chunk = @min(remaining, spaces.len);
        try w.writeAll(spaces[0..chunk]);
        remaining -= chunk;
    }
}

fn renderSourceLine(w: anytype, v: *View, line_idx: usize, width: usize) !void {
    const is_cursor_line = (v.active_pane == .source and line_idx == v.src_cursor);
    const line_num: u32 = @intCast(line_idx + 1);
    const is_highlighted = v.highlighted_source.contains(line_num);

    if (v.current_file_lines) |lines| {
        if (line_idx < lines.len) {
            const num_w: usize = 6;
            const content_w = width -| num_w;
            const line = lines[line_idx];
            const start = @min(v.src_hscroll, line.len);
            const visible = line[start..];
            const to_write = @min(visible.len, content_w);

            var color_buf: [4096]SyntaxColor = undefined;
            if (line.len < color_buf.len) {
                syntax.highlightZigLine(line, color_buf[0..line.len]);
            } else {
                @memset(color_buf[0..@min(line.len, color_buf.len)], .default);
            }
            const vis_colors = color_buf[start..][0..to_write];

            if (is_cursor_line) {
                try w.writeAll(ansi.bg_cursor_line);
                try w.print("{d:>5} ", .{line_num});
                try renderWithCharCursorColored(w, visible[0..to_write], vis_colors, v.src_col -| start);
                const written = num_w + to_write;
                if (written < width) try padSpaces(w, width - written);
                try w.writeAll(ansi.reset);
            } else if (is_highlighted) {
                try w.writeAll(ansi.style_highlight);
                try w.print("{d:>5} ", .{line_num});
                try w.writeAll(visible[0..to_write]);
                const written = num_w + to_write;
                if (written < width) try padSpaces(w, width - written);
                try w.writeAll(ansi.reset);
            } else {
                try w.print("{d:>5} ", .{line_num});
                try writeColoredText(w, visible[0..to_write], vis_colors);
                const written = num_w + to_write;
                if (written < width) try padSpaces(w, width - written);
            }
        } else {
            try w.writeAll(ansi.fg_dark_gray ++ "~" ++ ansi.reset);
            if (width > 1) try padSpaces(w, width - 1);
        }
    } else {
        if (line_idx == 0) {
            const msg = "<no source>";
            const to_write = @min(msg.len, width);
            try w.writeAll(msg[0..to_write]);
            if (to_write < width) try padSpaces(w, width - to_write);
        } else {
            try padSpaces(w, width);
        }
    }
}

fn renderDisasmLine(w: anytype, v: *View, line_idx: usize, width: usize) !void {
    const is_cursor_line = (v.active_pane == .disasm and line_idx == v.disasm_cursor);
    const is_highlighted = v.highlighted_disasm.contains(line_idx);

    if (line_idx < v.disasm_lines.len) {
        const dl = v.disasm_lines[line_idx];
        const text = dl.text;
        const start = @min(v.disasm_hscroll, text.len);
        const visible = text[start..];
        const to_write = @min(visible.len, width);

        var color_buf: [4096]SyntaxColor = undefined;
        if (text.len < color_buf.len) {
            syntax.highlightDisasm(text, dl.is_label, color_buf[0..text.len]);
        } else {
            @memset(color_buf[0..@min(text.len, color_buf.len)], .default);
        }
        const vis_colors = color_buf[start..][0..to_write];

        if (is_cursor_line) {
            try w.writeAll(ansi.bg_cursor_line);
            try renderWithCharCursorColored(w, visible[0..to_write], vis_colors, v.disasm_col -| start);
            if (to_write < width) try padSpaces(w, width - to_write);
            try w.writeAll(ansi.reset);
        } else if (is_highlighted) {
            try w.writeAll(ansi.style_highlight);
            try w.writeAll(visible[0..to_write]);
            if (to_write < width) try padSpaces(w, width - to_write);
            try w.writeAll(ansi.reset);
        } else {
            try writeColoredText(w, visible[0..to_write], vis_colors);
            if (to_write < width) try padSpaces(w, width - to_write);
        }
    } else {
        try padSpaces(w, width);
    }
}

fn renderStatusBar(w: anytype, v: *View, width: usize) !void {
    var status_buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&status_buf);
    const sw = fbs.writer();

    const file_name = if (v.current_file) |f| std.fs.path.basename(f) else "<none>";
    const src_line = v.src_cursor + 1;
    const src_col_display = v.src_col + 1;

    if (v.disasm_cursor < v.disasm_lines.len) {
        const dl = v.disasm_lines[v.disasm_cursor];
        sw.print(" {s}:{d}:{d}  |  0x{x}  |  {s}  |  gd=def gb=back /=file", .{
            file_name,
            src_line,
            src_col_display,
            dl.address,
            if (v.active_pane == .source) "SRC" else "ASM",
        }) catch {};
    } else {
        sw.print(" {s}:{d}:{d}  |  {s}  |  gd=def gb=back /=file", .{
            file_name,
            src_line,
            src_col_display,
            if (v.active_pane == .source) "SRC" else "ASM",
        }) catch {};
    }

    const status = fbs.getWritten();
    const to_write = @min(status.len, width);
    try w.writeAll(status[0..to_write]);
    if (to_write < width) try padSpaces(w, width - to_write);
}

fn writeColoredText(w: anytype, text: []const u8, colors: []const SyntaxColor) !void {
    var current: SyntaxColor = .default;
    for (text, colors) |byte, color| {
        if (color != current) {
            if (current != .default) try w.writeAll(ansi.fg_default);
            if (color != .default) try w.writeAll(color.escape());
            current = color;
        }
        try w.writeByte(byte);
    }
    if (current != .default) try w.writeAll(ansi.fg_default);
}

fn renderWithCharCursorColored(w: anytype, text: []const u8, colors: []const SyntaxColor, col: usize) !void {
    if (text.len == 0) return;
    const cursor_pos = @min(col, text.len);

    if (cursor_pos > 0)
        try writeColoredText(w, text[0..cursor_pos], colors[0..cursor_pos]);

    if (cursor_pos < text.len) {
        const c = colors[cursor_pos];
        if (c != .default) try w.writeAll(c.escape());
        try w.writeAll(ansi.reverse_video);
        try w.writeByte(text[cursor_pos]);
        try w.writeAll(ansi.reverse_video_off ++ ansi.bg_cursor_line);
        if (c != .default) try w.writeAll(ansi.fg_default);

        if (cursor_pos + 1 < text.len)
            try writeColoredText(w, text[cursor_pos + 1 ..], colors[cursor_pos + 1 ..]);
    }
}
