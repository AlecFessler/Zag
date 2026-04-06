const std = @import("std");
const debug_info = @import("debug_info.zig");
const disasm_mod = @import("disasm.zig");
const render = @import("render.zig");

const Allocator = std.mem.Allocator;
const Dwarf = std.debug.Dwarf;
const SourceKey = debug_info.SourceKey;
const DisasmIdxList = debug_info.DisasmIdxList;
const DisasmLine = disasm_mod.DisasmLine;
const Pane = render.Pane;

pub const NavEntry = struct {
    file: ?[]const u8,
    src_cursor: usize,
    src_col: usize,
    src_scroll: usize,
    disasm_cursor: usize,
    disasm_col: usize,
    disasm_scroll: usize,
    active_pane: Pane,
};

pub const NavState = struct {
    allocator: Allocator,
    dwarf: *Dwarf,

    // Source state
    current_file: ?[]const u8,
    current_file_lines: ?[][]const u8,
    source_cache: *std.StringHashMap([][]const u8),
    file_paths: *std.ArrayList([]const u8),
    reverse_map: *std.AutoHashMap(SourceKey, DisasmIdxList),
    src_cursor: usize,
    src_col: usize,
    src_scroll: usize,

    // Disasm state
    disasm_lines: []DisasmLine,
    addr_to_disasm: *std.AutoHashMap(u64, usize),
    disasm_cursor: usize,
    disasm_col: usize,
    disasm_scroll: usize,

    // UI
    active_pane: Pane,
    term_w: u16,
    term_h: u16,
    src_hscroll: usize,
    disasm_hscroll: usize,
    nav_stack: *std.ArrayList(NavEntry),
    highlighted_disasm: *std.AutoHashMap(usize, void),
    highlighted_source: *std.AutoHashMap(u32, void),
    dbg: ?std.fs.File,
};

pub fn setInitialView(nav: *NavState) void {
    for (nav.disasm_lines, 0..) |dl, i| {
        if (dl.is_label or dl.address == 0) continue;
        const cu = nav.dwarf.findCompileUnit(dl.address) catch continue;
        const sloc = nav.dwarf.getLineNumberInfo(nav.allocator, cu, dl.address) catch continue;
        nav.disasm_cursor = i;
        nav.current_file = sloc.file_name;
        nav.current_file_lines = loadSourceFileCached(nav, sloc.file_name);
        if (sloc.line > 0) {
            nav.src_cursor = @intCast(sloc.line - 1);
        }
        return;
    }
}

pub fn moveCursor(nav: *NavState, delta: i32) void {
    const height: usize = @as(usize, nav.term_h) -| 2;
    if (nav.active_pane == .source) {
        const max = if (nav.current_file_lines) |lines| lines.len else 1;
        if (max == 0) return;
        const new = @as(i64, @intCast(nav.src_cursor)) + delta;
        nav.src_cursor = @intCast(std.math.clamp(new, 0, @as(i64, @intCast(max -| 1))));
        render.ensureScroll(&nav.src_scroll, nav.src_cursor, height);
    } else {
        if (nav.disasm_lines.len == 0) return;
        const new = @as(i64, @intCast(nav.disasm_cursor)) + delta;
        nav.disasm_cursor = @intCast(std.math.clamp(new, 0, @as(i64, @intCast(nav.disasm_lines.len - 1))));
        render.ensureScroll(&nav.disasm_scroll, nav.disasm_cursor, height);
    }
}

pub fn updateHighlights(nav: *NavState) !void {
    nav.highlighted_disasm.clearRetainingCapacity();
    nav.highlighted_source.clearRetainingCapacity();

    if (nav.active_pane == .source) {
        if (nav.current_file) |file| {
            const file_idx = debug_info.resolveFileIdx(nav.file_paths, file);
            if (file_idx) |fi| {
                const key = SourceKey{ .file_idx = fi, .line = @intCast(nav.src_cursor + 1) };
                if (nav.reverse_map.get(key)) |indices| {
                    for (indices.items) |idx| {
                        try nav.highlighted_disasm.put(idx, {});
                    }
                    if (indices.items.len > 0) {
                        render.autoScroll(&nav.disasm_scroll, indices.items[0], nav.term_h -| 2);
                    }
                }
            }
        }
    } else {
        if (nav.disasm_cursor < nav.disasm_lines.len) {
            const dl = nav.disasm_lines[nav.disasm_cursor];
            if (!dl.is_label and dl.address != 0) {
                const cu = nav.dwarf.findCompileUnit(dl.address) catch return;
                const sloc = nav.dwarf.getLineNumberInfo(nav.allocator, cu, dl.address) catch return;

                if (nav.current_file == null or !std.mem.eql(u8, nav.current_file.?, sloc.file_name)) {
                    nav.current_file = sloc.file_name;
                    nav.current_file_lines = loadSourceFileCached(nav, sloc.file_name);
                }

                if (sloc.line > 0) {
                    const src_line: u32 = @intCast(sloc.line);
                    try nav.highlighted_source.put(src_line, {});
                    render.autoScroll(&nav.src_scroll, src_line -| 1, nav.term_h -| 2);
                }
            }
        }
    }
}

pub fn goToDefinition(nav: *NavState) void {
    if (nav.active_pane == .disasm) {
        goToDefDisasm(nav);
    } else {
        goToDefSource(nav);
    }
}

pub fn goBack(nav: *NavState) void {
    const entry = nav.nav_stack.pop() orelse return;
    nav.current_file = entry.file;
    nav.current_file_lines = if (entry.file) |f| loadSourceFileCached(nav, f) else null;
    nav.src_cursor = entry.src_cursor;
    nav.src_col = entry.src_col;
    nav.src_scroll = entry.src_scroll;
    nav.disasm_cursor = entry.disasm_cursor;
    nav.disasm_col = entry.disasm_col;
    nav.disasm_scroll = entry.disasm_scroll;
    nav.active_pane = entry.active_pane;
}

pub fn gotoFile(nav: *NavState, query: []const u8) void {
    var match: ?[]const u8 = null;
    for (nav.file_paths.items) |path| {
        if (std.mem.indexOf(u8, path, query) != null) {
            match = path;
            break;
        }
    }

    const target_path = match orelse return;

    nav.current_file = target_path;
    nav.current_file_lines = loadSourceFileCached(nav, target_path);
    nav.src_cursor = 0;
    nav.src_col = 0;
    nav.src_scroll = 0;
    nav.active_pane = .source;

    // Debug: dump ALL paths containing "main.zig"
    {
        var buf2: [2048]u8 = undefined;
        var fbs2 = std.io.fixedBufferStream(&buf2);
        const dw = fbs2.writer();
        dw.print("gotoFile: target='{s}' target_ptr={*} target_len={d}\n", .{ target_path, target_path.ptr, target_path.len }) catch {};
        for (nav.file_paths.items, 0..) |fp, fpi| {
            if (std.mem.indexOf(u8, fp, "main.zig") != null) {
                dw.print("  file_paths[{d}]='{s}' ptr={*} len={d} eql={}\n", .{ fpi, fp, fp.ptr, fp.len, std.mem.eql(u8, fp, target_path) }) catch {};
            }
        }
        dbgWrite(nav, fbs2.getWritten());
    }

    const file_idx = debug_info.resolveFileIdx(nav.file_paths, target_path) orelse {
        dbgWrite(nav, "gotoFile: resolveFileIdx returned null\n");
        return;
    };

    var best_disasm_idx: ?usize = null;
    var best_line: u32 = std.math.maxInt(u32);
    var match_count: usize = 0;

    var iter = nav.reverse_map.iterator();
    while (iter.next()) |entry| {
        if (entry.key_ptr.file_idx == file_idx) {
            match_count += 1;
            for (entry.value_ptr.items) |disasm_idx| {
                if (entry.key_ptr.line < best_line or
                    (entry.key_ptr.line == best_line and
                    (best_disasm_idx == null or disasm_idx < best_disasm_idx.?)))
                {
                    best_line = entry.key_ptr.line;
                    best_disasm_idx = disasm_idx;
                }
            }
        }
    }

    {
        var buf: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        fbs.writer().print("gotoFile: file_idx={d} matches={d} best_line={d}\n", .{ file_idx, match_count, best_line }) catch {};
        dbgWrite(nav, fbs.getWritten());
    }

    if (best_disasm_idx) |idx| {
        nav.disasm_cursor = idx;
        nav.disasm_scroll = idx;
    }
    if (best_line != std.math.maxInt(u32) and best_line > 0) {
        nav.src_cursor = best_line - 1;
    }
}

pub fn wordForward(nav: *NavState) void {
    const line = cursorLine(nav);
    if (line.len == 0) return;
    var col = if (nav.active_pane == .source) nav.src_col else nav.disasm_col;
    while (col < line.len and isIdentChar(line[col])) col += 1;
    while (col < line.len and !isIdentChar(line[col])) col += 1;
    col = @min(col, line.len -| 1);
    if (nav.active_pane == .source) nav.src_col = col else nav.disasm_col = col;
}

pub fn wordBackward(nav: *NavState) void {
    const line = cursorLine(nav);
    if (line.len == 0) return;
    var col = if (nav.active_pane == .source) nav.src_col else nav.disasm_col;
    if (col == 0) return;
    col -= 1;
    while (col > 0 and !isIdentChar(line[col])) col -= 1;
    while (col > 0 and isIdentChar(line[col - 1])) col -= 1;
    if (nav.active_pane == .source) nav.src_col = col else nav.disasm_col = col;
}

pub fn clampCol(nav: *NavState) void {
    const line = cursorLine(nav);
    const max = if (line.len > 0) line.len - 1 else 0;
    if (nav.active_pane == .source) {
        nav.src_col = @min(nav.src_col, max);
    } else {
        nav.disasm_col = @min(nav.disasm_col, max);
    }
}

pub fn cursorLine(nav: *const NavState) []const u8 {
    if (nav.active_pane == .source) {
        if (nav.current_file_lines) |lines| {
            if (nav.src_cursor < lines.len) return lines[nav.src_cursor];
        }
        return "";
    } else {
        if (nav.disasm_cursor < nav.disasm_lines.len) return nav.disasm_lines[nav.disasm_cursor].text;
        return "";
    }
}

fn pushNav(nav: *NavState) void {
    nav.nav_stack.append(nav.allocator, .{
        .file = nav.current_file,
        .src_cursor = nav.src_cursor,
        .src_col = nav.src_col,
        .src_scroll = nav.src_scroll,
        .disasm_cursor = nav.disasm_cursor,
        .disasm_col = nav.disasm_col,
        .disasm_scroll = nav.disasm_scroll,
        .active_pane = nav.active_pane,
    }) catch {};
}

fn goToDefDisasm(nav: *NavState) void {
    if (nav.disasm_cursor >= nav.disasm_lines.len) return;
    const dl = nav.disasm_lines[nav.disasm_cursor];
    if (dl.is_label) return;

    const text = dl.text;
    const colon_space = std.mem.indexOf(u8, text, ": ") orelse return;
    const instr = text[colon_space + 2 ..];

    const is_call = std.mem.startsWith(u8, instr, "call ");
    const is_jmp = std.mem.startsWith(u8, instr, "jmp ");
    if (!is_call and !is_jmp) return;

    const skip = if (is_call) @as(usize, 5) else 4;
    const operand = std.mem.trimLeft(u8, instr[skip..], " ");

    const target_addr = disasm_mod.parseHexAddr(operand) orelse return;
    const target_idx = nav.addr_to_disasm.get(target_addr) orelse return;

    pushNav(nav);

    nav.disasm_cursor = target_idx;
    nav.disasm_col = 0;
    const height: usize = @as(usize, nav.term_h) -| 2;
    render.autoScroll(&nav.disasm_scroll, target_idx, @intCast(height));
    render.ensureScroll(&nav.disasm_scroll, nav.disasm_cursor, height);

    if (target_idx < nav.disasm_lines.len) {
        const target_dl = nav.disasm_lines[target_idx];
        if (!target_dl.is_label and target_dl.address != 0) {
            const cu = nav.dwarf.findCompileUnit(target_dl.address) catch return;
            const sloc = nav.dwarf.getLineNumberInfo(nav.allocator, cu, target_dl.address) catch return;
            nav.current_file = sloc.file_name;
            nav.current_file_lines = loadSourceFileCached(nav, sloc.file_name);
            if (sloc.line > 0) {
                nav.src_cursor = @intCast(sloc.line - 1);
                nav.src_col = 0;
            }
        }
    }
}

fn goToDefSource(nav: *NavState) void {
    const word = wordUnderCursor(nav) orelse return;

    for (nav.disasm_lines, 0..) |dl, i| {
        if (!dl.is_label) continue;
        if (std.mem.indexOf(u8, dl.text, word) != null) {
            pushNav(nav);
            const target = if (i + 1 < nav.disasm_lines.len and !nav.disasm_lines[i + 1].is_label)
                i + 1
            else
                i;
            nav.disasm_cursor = target;
            nav.disasm_col = 0;
            nav.active_pane = .disasm;
            const height: usize = @as(usize, nav.term_h) -| 2;
            render.autoScroll(&nav.disasm_scroll, target, @intCast(height));
            render.ensureScroll(&nav.disasm_scroll, nav.disasm_cursor, height);

            if (target < nav.disasm_lines.len) {
                const target_dl = nav.disasm_lines[target];
                if (!target_dl.is_label and target_dl.address != 0) {
                    const cu = nav.dwarf.findCompileUnit(target_dl.address) catch return;
                    const sloc = nav.dwarf.getLineNumberInfo(nav.allocator, cu, target_dl.address) catch return;
                    nav.current_file = sloc.file_name;
                    nav.current_file_lines = loadSourceFileCached(nav, sloc.file_name);
                    if (sloc.line > 0) {
                        nav.src_cursor = @intCast(sloc.line - 1);
                        nav.src_col = 0;
                    }
                }
            }
            return;
        }
    }
}

fn wordUnderCursor(nav: *const NavState) ?[]const u8 {
    if (nav.current_file_lines == null) return null;
    const lines = nav.current_file_lines.?;
    if (nav.src_cursor >= lines.len) return null;
    const line = lines[nav.src_cursor];
    if (line.len == 0) return null;
    const col = @min(nav.src_col, line.len -| 1);

    if (!isIdentChar(line[col])) return null;

    var start = col;
    while (start > 0 and isIdentChar(line[start - 1])) start -= 1;
    var end = col + 1;
    while (end < line.len and isIdentChar(line[end])) end += 1;

    if (start == end) return null;
    return line[start..end];
}

fn isIdentChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn loadSourceFileCached(nav: *NavState, path: []const u8) ?[][]const u8 {
    if (nav.source_cache.get(path)) |lines| return lines;
    const lines = debug_info.loadSourceFile(nav.allocator, path) orelse return null;
    nav.source_cache.put(path, lines) catch {};
    return lines;
}

fn dbgWrite(nav: *NavState, msg: []const u8) void {
    if (nav.dbg) |f| f.writeAll(msg) catch {};
}
