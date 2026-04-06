const std = @import("std");

const ansi = @import("src/ansi.zig");
const cli = @import("src/cli.zig");
const debug_info = @import("src/debug_info.zig");
const disasm = @import("src/disasm.zig");
const input = @import("src/input.zig");
const navigation = @import("src/navigation.zig");
const render = @import("src/render.zig");
const terminal = @import("src/terminal.zig");

const Allocator = std.mem.Allocator;

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len < 2) {
        _ = std.posix.write(2, cli.usage_text) catch {};
        std.process.exit(1);
    }

    // Parse flags
    var elf_path: ?[]const u8 = null;
    var query: cli.CliQuery = .none;
    var query_arg: ?[]const u8 = null;
    var context_lines: usize = 5;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--list-files")) {
            query = .list_files;
        } else if (std.mem.eql(u8, arg, "--source")) {
            query = .source;
            i += 1;
            if (i < args.len) query_arg = args[i];
        } else if (std.mem.eql(u8, arg, "--disasm")) {
            query = .disasm;
            i += 1;
            if (i < args.len) query_arg = args[i];
        } else if (std.mem.eql(u8, arg, "--func")) {
            query = .func;
            i += 1;
            if (i < args.len) query_arg = args[i];
        } else if (std.mem.eql(u8, arg, "--dump-map")) {
            query = .dump_map;
            i += 1;
            if (i < args.len) query_arg = args[i];
        } else if (std.mem.eql(u8, arg, "--context") or std.mem.eql(u8, arg, "-C")) {
            i += 1;
            if (i < args.len) context_lines = std.fmt.parseInt(usize, args[i], 10) catch 5;
        } else if (arg[0] != '-') {
            elf_path = arg;
        }
    }

    const path = elf_path orelse {
        _ = std.posix.write(2, cli.usage_text) catch {};
        std.process.exit(1);
    };

    // Load ELF + DWARF
    var dwarf = try debug_info.loadDwarf(gpa, path);

    // Run objdump and parse
    const objdump_output = try disasm.runObjdump(gpa, path);
    var disasm_lines_list: std.ArrayList(disasm.DisasmLine) = .empty;
    var addr_to_disasm = std.AutoHashMap(u64, usize).init(gpa);
    disasm.parseDisasm(gpa, objdump_output, &disasm_lines_list, &addr_to_disasm);
    const disasm_lines = try disasm_lines_list.toOwnedSlice(gpa);

    // Build reverse map
    var file_paths: std.ArrayList([]const u8) = .empty;
    var reverse_map = std.AutoHashMap(debug_info.SourceKey, debug_info.DisasmIdxList).init(gpa);
    try debug_info.buildReverseMap(gpa, &dwarf, &addr_to_disasm, &file_paths, &reverse_map);

    // CLI query mode
    if (query != .none) {
        try cli.cliMode(gpa, query, query_arg, context_lines, &dwarf, disasm_lines, &addr_to_disasm, &file_paths, &reverse_map);
        return;
    }

    // TUI mode
    const tty = try std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_write });
    const orig_termios = try std.posix.tcgetattr(tty.handle);
    terminal.enableRawMode(tty.handle, orig_termios);
    const ws = terminal.getWinSize(tty.handle);

    try tty.writeAll(ansi.alt_screen_enable ++ ansi.cursor_hide);

    const dbg_file = std.fs.cwd().createFile("/home/alec/ba_tui_debug.log", .{}) catch null;

    var source_cache = std.StringHashMap([][]const u8).init(gpa);
    var highlighted_disasm = std.AutoHashMap(usize, void).init(gpa);
    var highlighted_source = std.AutoHashMap(u32, void).init(gpa);
    var nav_stack: std.ArrayList(navigation.NavEntry) = .empty;

    var nav = navigation.NavState{
        .allocator = gpa,
        .dwarf = &dwarf,
        .current_file = null,
        .current_file_lines = null,
        .source_cache = &source_cache,
        .file_paths = &file_paths,
        .reverse_map = &reverse_map,
        .src_cursor = 0,
        .src_col = 0,
        .src_scroll = 0,
        .disasm_lines = disasm_lines,
        .addr_to_disasm = &addr_to_disasm,
        .disasm_cursor = 0,
        .disasm_col = 0,
        .disasm_scroll = 0,
        .active_pane = .disasm,
        .term_w = ws.cols,
        .term_h = ws.rows,
        .src_hscroll = 0,
        .disasm_hscroll = 0,
        .nav_stack = &nav_stack,
        .highlighted_disasm = &highlighted_disasm,
        .highlighted_source = &highlighted_source,
        .dbg = dbg_file,
    };

    navigation.setInitialView(&nav);
    try navigation.updateHighlights(&nav);

    while (true) {
        var view = viewFromNav(&nav, tty);
        try render.render(&view);
        syncNavFromView(&nav, &view);

        const action = try input.readInput(tty);
        switch (action) {
            .quit => break,
            .down => {
                navigation.moveCursor(&nav, 1);
                navigation.clampCol(&nav);
                try navigation.updateHighlights(&nav);
            },
            .up => {
                navigation.moveCursor(&nav, -1);
                navigation.clampCol(&nav);
                try navigation.updateHighlights(&nav);
            },
            .left => {
                if (nav.active_pane == .source) {
                    nav.src_col -|= 1;
                } else {
                    nav.disasm_col -|= 1;
                }
            },
            .right => {
                if (nav.active_pane == .source) {
                    nav.src_col += 1;
                } else {
                    nav.disasm_col += 1;
                }
                navigation.clampCol(&nav);
            },
            .tab => {
                nav.active_pane = if (nav.active_pane == .source) .disasm else .source;
            },
            .half_page_down => {
                const half = ws.rows / 2;
                navigation.moveCursor(&nav, @intCast(half));
                navigation.clampCol(&nav);
                try navigation.updateHighlights(&nav);
            },
            .half_page_up => {
                const half = ws.rows / 2;
                navigation.moveCursor(&nav, -@as(i32, @intCast(half)));
                navigation.clampCol(&nav);
                try navigation.updateHighlights(&nav);
            },
            .goto_file => {
                if (try readPrompt(&nav, tty, ws, "file: ")) |query_str| {
                    navigation.gotoFile(&nav, query_str);
                    try navigation.updateHighlights(&nav);
                }
            },
            .goto_def => {
                navigation.goToDefinition(&nav);
                try navigation.updateHighlights(&nav);
            },
            .go_back => {
                navigation.goBack(&nav);
                try navigation.updateHighlights(&nav);
            },
            .word_forward => {
                navigation.wordForward(&nav);
            },
            .word_backward => {
                navigation.wordBackward(&nav);
            },
            .line_start => {
                if (nav.active_pane == .source) nav.src_col = 0 else nav.disasm_col = 0;
            },
            .line_end => {
                const line = navigation.cursorLine(&nav);
                const end = if (line.len > 0) line.len - 1 else 0;
                if (nav.active_pane == .source) nav.src_col = end else nav.disasm_col = end;
            },
            .none => {},
        }
    }

    try tty.writeAll(ansi.cursor_show ++ ansi.alt_screen_disable);
    try std.posix.tcsetattr(tty.handle, .FLUSH, orig_termios);
}

fn viewFromNav(nav: *navigation.NavState, tty: std.fs.File) render.View {
    return .{
        .allocator = nav.allocator,
        .tty = tty,
        .term_w = nav.term_w,
        .term_h = nav.term_h,
        .current_file = nav.current_file,
        .current_file_lines = nav.current_file_lines,
        .src_cursor = nav.src_cursor,
        .src_col = nav.src_col,
        .src_scroll = nav.src_scroll,
        .src_hscroll = nav.src_hscroll,
        .highlighted_source = nav.highlighted_source,
        .disasm_lines = nav.disasm_lines,
        .disasm_cursor = nav.disasm_cursor,
        .disasm_col = nav.disasm_col,
        .disasm_scroll = nav.disasm_scroll,
        .disasm_hscroll = nav.disasm_hscroll,
        .highlighted_disasm = nav.highlighted_disasm,
        .active_pane = nav.active_pane,
    };
}

fn syncNavFromView(nav: *navigation.NavState, view: *render.View) void {
    nav.src_scroll = view.src_scroll;
    nav.disasm_scroll = view.disasm_scroll;
}

fn readPrompt(nav: *navigation.NavState, tty: std.fs.File, ws: terminal.WinSize, prompt: []const u8) !?[]const u8 {
    var buf: [256]u8 = undefined;
    var len: usize = 0;

    while (true) {
        try render.renderPrompt(nav.allocator, tty, ws.cols, ws.rows, prompt, buf[0..len]);

        var byte: [1]u8 = undefined;
        const n = try tty.read(&byte);
        if (n == 0) return null;

        switch (byte[0]) {
            ansi.key_newline, ansi.key_enter => {
                if (len == 0) return null;
                return buf[0..len];
            },
            ansi.key_escape => return null,
            ansi.key_backspace, ansi.key_backspace_alt => {
                len -|= 1;
            },
            else => {
                if (byte[0] >= 0x20 and len < buf.len) {
                    buf[len] = byte[0];
                    len += 1;
                }
            },
        }
    }
}
