const std = @import("std");

const Allocator = std.mem.Allocator;
const Dwarf = std.debug.Dwarf;
const elf = std.elf;

// ── Data types ──────────────────────────────────────────────────────────────

const DisasmLine = struct {
    address: u64,
    text: []const u8,
    is_label: bool,
};

const SourceKey = struct {
    file_idx: u32,
    line: u32,
};

const Pane = enum { source, disasm };

const DisasmIdxList = std.ArrayList(usize);

const App = struct {
    allocator: Allocator,
    dwarf: Dwarf,

    // Disassembly
    disasm_lines: []DisasmLine,
    addr_to_disasm: std.AutoHashMap(u64, usize),

    // Source mapping
    file_paths: std.ArrayList([]const u8),
    file_path_map: std.StringHashMap(u32),
    reverse_map: std.AutoHashMap(SourceKey, DisasmIdxList),
    source_cache: std.StringHashMap([][]const u8),

    // UI state
    active_pane: Pane,
    src_cursor: usize,
    src_col: usize,
    src_scroll: usize,
    src_hscroll: usize,
    disasm_cursor: usize,
    disasm_col: usize,
    disasm_scroll: usize,
    disasm_hscroll: usize,
    current_file: ?[]const u8,
    current_file_lines: ?[][]const u8,
    highlighted_disasm: std.AutoHashMap(usize, void),
    highlighted_source: std.AutoHashMap(u32, void),

    // Navigation stack for gd/gb
    nav_stack: std.ArrayList(NavEntry),

    // Terminal
    term_w: u16,
    term_h: u16,
    tty: std.fs.File,
    orig_termios: std.posix.termios,

    fn cursorLine(app: *const App) []const u8 {
        if (app.active_pane == .source) {
            if (app.current_file_lines) |lines| {
                if (app.src_cursor < lines.len) return lines[app.src_cursor];
            }
            return "";
        } else {
            if (app.disasm_cursor < app.disasm_lines.len) return app.disasm_lines[app.disasm_cursor].text;
            return "";
        }
    }

    fn cursorCol(app: *const App) usize {
        return if (app.active_pane == .source) app.src_col else app.disasm_col;
    }

    fn clampCol(app: *App) void {
        const line = app.cursorLine();
        const max = if (line.len > 0) line.len - 1 else 0;
        if (app.active_pane == .source) {
            app.src_col = @min(app.src_col, max);
        } else {
            app.disasm_col = @min(app.disasm_col, max);
        }
    }
};

const NavEntry = struct {
    file: ?[]const u8,
    src_cursor: usize,
    src_col: usize,
    src_scroll: usize,
    disasm_cursor: usize,
    disasm_col: usize,
    disasm_scroll: usize,
    active_pane: Pane,
};

const CliQuery = enum { none, list_files, source, disasm, func };

// ── Main ────────────────────────────────────────────────────────────────────

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len < 2) {
        _ = std.posix.write(2, usage_text) catch {};
        std.process.exit(1);
    }

    // Parse flags — query mode if any --flag is present
    var elf_path: ?[]const u8 = null;
    var query: CliQuery = .none;
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
        } else if (std.mem.eql(u8, arg, "--context") or std.mem.eql(u8, arg, "-C")) {
            i += 1;
            if (i < args.len) context_lines = std.fmt.parseInt(usize, args[i], 10) catch 5;
        } else if (arg[0] != '-') {
            elf_path = arg;
        }
    }

    const path = elf_path orelse {
        _ = std.posix.write(2, usage_text) catch {};
        std.process.exit(1);
    };

    // Load ELF + DWARF
    var dwarf = try loadDwarf(gpa, path);

    // Run objdump and parse
    const objdump_output = try runObjdump(gpa, path);
    var disasm_lines_list: std.ArrayList(DisasmLine) = .empty;
    var addr_to_disasm = std.AutoHashMap(u64, usize).init(gpa);
    parseDisasm(gpa, objdump_output, &disasm_lines_list, &addr_to_disasm);
    const disasm_lines = try disasm_lines_list.toOwnedSlice(gpa);

    // Build reverse map
    var file_paths: std.ArrayList([]const u8) = .empty;
    var file_path_map = std.StringHashMap(u32).init(gpa);
    var reverse_map = std.AutoHashMap(SourceKey, DisasmIdxList).init(gpa);
    try buildReverseMap(gpa, &dwarf, &addr_to_disasm, &file_paths, &file_path_map, &reverse_map);

    // CLI query mode
    if (query != .none) {
        try cliMode(gpa, query, query_arg, context_lines, &dwarf, disasm_lines, &addr_to_disasm, &file_paths, &file_path_map, &reverse_map);
        return;
    }

    // TUI mode
    const tty = try std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_write });
    const orig_termios = try std.posix.tcgetattr(tty.handle);
    enableRawMode(tty.handle, orig_termios);
    const ws = getWinSize(tty.handle);

    try tty.writeAll("\x1b[?1049h\x1b[?25l");

    var app = App{
        .allocator = gpa,
        .dwarf = dwarf,
        .disasm_lines = disasm_lines,
        .addr_to_disasm = addr_to_disasm,
        .file_paths = file_paths,
        .file_path_map = file_path_map,
        .reverse_map = reverse_map,
        .source_cache = std.StringHashMap([][]const u8).init(gpa),
        .active_pane = .disasm,
        .src_cursor = 0,
        .src_col = 0,
        .src_scroll = 0,
        .src_hscroll = 0,
        .disasm_cursor = 0,
        .disasm_col = 0,
        .disasm_scroll = 0,
        .disasm_hscroll = 0,
        .current_file = null,
        .current_file_lines = null,
        .highlighted_disasm = std.AutoHashMap(usize, void).init(gpa),
        .highlighted_source = std.AutoHashMap(u32, void).init(gpa),
        .nav_stack = .empty,
        .term_w = ws.cols,
        .term_h = ws.rows,
        .tty = tty,
        .orig_termios = orig_termios,
    };

    setInitialView(&app);
    try updateHighlights(&app);

    while (true) {
        try render(&app);
        const action = try readInput(tty);
        switch (action) {
            .quit => break,
            .down => {
                moveCursor(&app, 1);
                app.clampCol();
                try updateHighlights(&app);
            },
            .up => {
                moveCursor(&app, -1);
                app.clampCol();
                try updateHighlights(&app);
            },
            .left => {
                if (app.active_pane == .source) {
                    app.src_col -|= 1;
                } else {
                    app.disasm_col -|= 1;
                }
            },
            .right => {
                if (app.active_pane == .source) {
                    app.src_col += 1;
                } else {
                    app.disasm_col += 1;
                }
                app.clampCol();
            },
            .tab => {
                app.active_pane = if (app.active_pane == .source) .disasm else .source;
            },
            .half_page_down => {
                const half = app.term_h / 2;
                moveCursor(&app, @intCast(half));
                app.clampCol();
                try updateHighlights(&app);
            },
            .half_page_up => {
                const half = app.term_h / 2;
                moveCursor(&app, -@as(i32, @intCast(half)));
                app.clampCol();
                try updateHighlights(&app);
            },
            .goto_file => {
                if (try readPrompt(&app, "file: ")) |query_str| {
                    gotoFile(&app, query_str);
                    try updateHighlights(&app);
                }
            },
            .goto_def => {
                goToDefinition(&app);
                try updateHighlights(&app);
            },
            .go_back => {
                goBack(&app);
                try updateHighlights(&app);
            },
            .word_forward => {
                wordForward(&app);
            },
            .word_backward => {
                wordBackward(&app);
            },
            .line_start => {
                if (app.active_pane == .source) app.src_col = 0 else app.disasm_col = 0;
            },
            .line_end => {
                const line = app.cursorLine();
                const end = if (line.len > 0) line.len - 1 else 0;
                if (app.active_pane == .source) app.src_col = end else app.disasm_col = end;
            },
            .none => {},
        }
    }

    try tty.writeAll("\x1b[?25h\x1b[?1049l");
    try std.posix.tcsetattr(tty.handle, .FLUSH, orig_termios);
}

const usage_text =
    \\Usage: bin_analyzer <elf-binary> [options]
    \\
    \\  No options: launch interactive TUI
    \\
    \\  --list-files           List all source files in debug info
    \\  --source <file:line>   Show source line and its disassembly
    \\  --disasm <addr>        Show disassembly at address and its source
    \\  --func <name>          Find function by name, show location + disasm
    \\  -C, --context <n>      Lines of context around matches (default 5)
    \\
;

// ── CLI query mode ──────────────────────────────────────────────────────────

fn cliMode(
    gpa: Allocator,
    query: CliQuery,
    query_arg: ?[]const u8,
    context_lines: usize,
    dwarf: *Dwarf,
    disasm_lines: []DisasmLine,
    addr_to_disasm: *std.AutoHashMap(u64, usize),
    file_paths: *std.ArrayList([]const u8),
    file_path_map: *std.StringHashMap(u32),
    reverse_map: *std.AutoHashMap(SourceKey, DisasmIdxList),
) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const w = out.writer(gpa);

    switch (query) {
        .list_files => {
            try w.writeAll("Source files in debug info:\n");
            for (file_paths.items) |path| {
                try w.print("  {s}\n", .{path});
            }
        },
        .source => {
            const arg = query_arg orelse {
                try w.writeAll("Error: --source requires <file:line> argument\n");
                try writeOut(out.items);
                return;
            };
            try cliSource(gpa, w, arg, context_lines, dwarf, disasm_lines, file_paths, file_path_map, reverse_map);
        },
        .disasm => {
            const arg = query_arg orelse {
                try w.writeAll("Error: --disasm requires <addr> argument\n");
                try writeOut(out.items);
                return;
            };
            try cliDisasm(gpa, w, arg, context_lines, dwarf, disasm_lines, addr_to_disasm);
        },
        .func => {
            const arg = query_arg orelse {
                try w.writeAll("Error: --func requires <name> argument\n");
                try writeOut(out.items);
                return;
            };
            try cliFunc(gpa, w, arg, context_lines, dwarf, disasm_lines);
        },
        .none => {},
    }

    try writeOut(out.items);
}

fn writeOut(data: []const u8) !void {
    _ = std.posix.write(1, data) catch return error.WriteError;
}

fn cliSource(
    gpa: Allocator,
    w: anytype,
    arg: []const u8,
    context_lines: usize,
    dwarf: *Dwarf,
    disasm_lines: []DisasmLine,
    file_paths: *std.ArrayList([]const u8),
    file_path_map: *std.StringHashMap(u32),
    reverse_map: *std.AutoHashMap(SourceKey, DisasmIdxList),
) !void {
    // Parse "file:line" or "file" (shows first lines)
    const colon = std.mem.lastIndexOfScalar(u8, arg, ':');
    const file_query = if (colon) |c| arg[0..c] else arg;
    const target_line: ?u32 = if (colon) |c| std.fmt.parseInt(u32, arg[c + 1 ..], 10) catch null else null;

    // Find matching file
    var match_path: ?[]const u8 = null;
    for (file_paths.items) |path| {
        if (std.mem.indexOf(u8, path, file_query) != null) {
            match_path = path;
            break;
        }
    }

    const file_path = match_path orelse {
        try w.print("No file matching '{s}' found in debug info.\nUse --list-files to see available files.\n", .{file_query});
        return;
    };

    try w.print("── {s} ──\n", .{file_path});

    // Load source
    const source = loadSourceFileStatic(gpa, file_path);
    const line_num = target_line orelse 1;

    if (source) |lines| {
        const start = if (line_num > context_lines) line_num - context_lines else 1;
        const end = @min(line_num + context_lines, @as(u32, @intCast(lines.len)));

        try w.writeAll("\nSource:\n");
        for (start..end + 1) |ln| {
            const marker: u8 = if (ln == line_num) '>' else ' ';
            if (ln - 1 < lines.len) {
                try w.print("  {c} {d:>5} | {s}\n", .{ marker, ln, lines[ln - 1] });
            }
        }
    } else {
        try w.writeAll("  (source file not found on disk)\n");
    }

    // Show corresponding disasm
    const file_idx = file_path_map.get(file_path) orelse resolveFileIdxStatic(file_paths, file_path) orelse return;
    if (target_line) |tl| {
        const key = SourceKey{ .file_idx = file_idx, .line = tl };
        if (reverse_map.get(key)) |indices| {
            try w.writeAll("\nDisassembly:\n");
            for (indices.items) |idx| {
                if (idx < disasm_lines.len) {
                    try w.print("  {s}\n", .{disasm_lines[idx].text});
                }
            }
        } else {
            try w.writeAll("\n  (no disassembly for this line)\n");
        }
    } else {
        // Show disasm for first few lines that have mappings
        try w.writeAll("\nDisassembly (first mapped lines):\n");
        var shown: usize = 0;
        var ln: u32 = 1;
        while (ln < 200 and shown < 20) : (ln += 1) {
            const key = SourceKey{ .file_idx = file_idx, .line = ln };
            if (reverse_map.get(key)) |indices| {
                for (indices.items) |idx| {
                    if (idx < disasm_lines.len) {
                        try w.print("  {s}\n", .{disasm_lines[idx].text});
                        shown += 1;
                    }
                }
            }
        }
    }

    _ = dwarf;
}

fn cliDisasm(
    gpa: Allocator,
    w: anytype,
    arg: []const u8,
    context_lines: usize,
    dwarf: *Dwarf,
    disasm_lines: []DisasmLine,
    addr_to_disasm: *std.AutoHashMap(u64, usize),
) !void {
    const addr = parseHexAddr(arg) orelse {
        try w.print("Error: cannot parse address '{s}'\n", .{arg});
        return;
    };

    // Find in disasm — exact match or closest
    const idx = addr_to_disasm.get(addr) orelse blk: {
        // Find closest
        var best: ?usize = null;
        var best_diff: u64 = std.math.maxInt(u64);
        for (disasm_lines, 0..) |dl, di| {
            if (dl.is_label or dl.address == 0) continue;
            const diff = if (dl.address >= addr) dl.address - addr else addr - dl.address;
            if (diff < best_diff) {
                best_diff = diff;
                best = di;
            }
        }
        break :blk best orelse {
            try w.print("Address 0x{x} not found in disassembly.\n", .{addr});
            return;
        };
    };

    // Show disasm context
    try w.print("── Disassembly around 0x{x} ──\n\n", .{addr});
    const start = idx -| context_lines;
    const end = @min(idx + context_lines + 1, disasm_lines.len);
    for (start..end) |di| {
        const marker: u8 = if (di == idx) '>' else ' ';
        try w.print("  {c} {s}\n", .{ marker, disasm_lines[di].text });
    }

    // Show source location
    if (idx < disasm_lines.len) {
        const dl = disasm_lines[idx];
        if (!dl.is_label and dl.address != 0) {
            const cu = dwarf.findCompileUnit(dl.address) catch return;
            const sloc = dwarf.getLineNumberInfo(gpa, cu, dl.address) catch return;
            try w.print("\n── Source: {s}:{d} ──\n\n", .{ sloc.file_name, sloc.line });

            if (loadSourceFileStatic(gpa, sloc.file_name)) |lines| {
                const src_line: u32 = @intCast(sloc.line);
                const s = if (src_line > context_lines) src_line - context_lines else 1;
                const e = @min(src_line + context_lines, @as(u32, @intCast(lines.len)));
                for (s..e + 1) |ln| {
                    const m: u8 = if (ln == src_line) '>' else ' ';
                    if (ln - 1 < lines.len) {
                        try w.print("  {c} {d:>5} | {s}\n", .{ m, ln, lines[ln - 1] });
                    }
                }
            } else {
                try w.writeAll("  (source file not found on disk)\n");
            }
        }
    }
}

fn cliFunc(
    gpa: Allocator,
    w: anytype,
    name: []const u8,
    context_lines: usize,
    dwarf: *Dwarf,
    disasm_lines: []DisasmLine,
) !void {
    // Search labels for function name
    var found = false;
    for (disasm_lines, 0..) |dl, di| {
        if (!dl.is_label) continue;
        if (std.mem.indexOf(u8, dl.text, name) == null) continue;

        found = true;
        try w.print("── {s} ──\n\n", .{dl.text});

        // Show instructions following the label
        try w.writeAll("Disassembly:\n");
        var count: usize = 0;
        var ii = di + 1;
        while (ii < disasm_lines.len and count < context_lines * 2 + 10) : (ii += 1) {
            if (disasm_lines[ii].is_label) break; // next function
            try w.print("  {s}\n", .{disasm_lines[ii].text});
            count += 1;
        }

        // Source location from first instruction
        if (di + 1 < disasm_lines.len) {
            const first_instr = disasm_lines[di + 1];
            if (!first_instr.is_label and first_instr.address != 0) {
                const cu = dwarf.findCompileUnit(first_instr.address) catch continue;
                const sloc = dwarf.getLineNumberInfo(gpa, cu, first_instr.address) catch continue;
                try w.print("\nDefined at: {s}:{d}\n", .{ sloc.file_name, sloc.line });

                if (loadSourceFileStatic(gpa, sloc.file_name)) |lines| {
                    const src_line: u32 = @intCast(sloc.line);
                    const s = if (src_line > context_lines) src_line - context_lines else 1;
                    const e = @min(src_line + context_lines, @as(u32, @intCast(lines.len)));
                    try w.writeAll("\nSource:\n");
                    for (s..e + 1) |ln| {
                        const m: u8 = if (ln == src_line) '>' else ' ';
                        if (ln - 1 < lines.len) {
                            try w.print("  {c} {d:>5} | {s}\n", .{ m, ln, lines[ln - 1] });
                        }
                    }
                }
            }
        }
        try w.writeByte('\n');
    }

    if (!found) {
        try w.print("No function matching '{s}' found.\n", .{name});
    }
}

fn loadSourceFileStatic(gpa: Allocator, path: []const u8) ?[][]const u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    const content = file.readToEndAlloc(gpa, std.math.maxInt(u32)) catch return null;

    var lines_list: std.ArrayList([]const u8) = .empty;
    var iter = std.mem.splitScalar(u8, content, '\n');
    while (iter.next()) |line| {
        lines_list.append(gpa, line) catch return null;
    }
    return lines_list.toOwnedSlice(gpa) catch null;
}

fn resolveFileIdxStatic(file_paths: *std.ArrayList([]const u8), file: []const u8) ?u32 {
    const basename = std.fs.path.basename(file);
    for (file_paths.items, 0..) |path, idx| {
        if (std.mem.endsWith(u8, path, basename)) return @intCast(idx);
    }
    return null;
}

// ── ELF / DWARF loading ────────────────────────────────────────────────────

fn loadDwarf(gpa: Allocator, path: []const u8) !Dwarf {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const bytes = try file.readToEndAlloc(gpa, std.math.maxInt(u32));

    const hdr_sz = @sizeOf(elf.Elf64_Ehdr);
    if (bytes.len < hdr_sz) return error.InvalidElfFile;

    var rd = std.Io.Reader.fixed(bytes[0..hdr_sz]);
    const elf_hdr = try elf.Header.read(&rd);

    var dwarf: Dwarf = .{
        .endian = elf_hdr.endian,
        .is_macho = false,
    };

    const shdrs = std.mem.bytesAsSlice(
        elf.Elf64_Shdr,
        bytes[elf_hdr.shoff .. elf_hdr.shoff + elf_hdr.shentsize * elf_hdr.shnum],
    );
    const shstr_shdr = shdrs[elf_hdr.shstrndx];
    const shstr = bytes[shstr_shdr.sh_offset .. shstr_shdr.sh_offset + shstr_shdr.sh_size];

    var shdr_itr = elf_hdr.iterateSectionHeadersBuffer(bytes);
    while (try shdr_itr.next()) |shdr| {
        const name = getCStrAt(shstr, @intCast(shdr.sh_name)) orelse continue;
        const dwarf_idx: ?usize = if (std.mem.eql(u8, name, ".debug_info"))
            @intFromEnum(Dwarf.Section.Id.debug_info)
        else if (std.mem.eql(u8, name, ".debug_abbrev"))
            @intFromEnum(Dwarf.Section.Id.debug_abbrev)
        else if (std.mem.eql(u8, name, ".debug_str"))
            @intFromEnum(Dwarf.Section.Id.debug_str)
        else if (std.mem.eql(u8, name, ".debug_str_offsets"))
            @intFromEnum(Dwarf.Section.Id.debug_str_offsets)
        else if (std.mem.eql(u8, name, ".debug_line"))
            @intFromEnum(Dwarf.Section.Id.debug_line)
        else if (std.mem.eql(u8, name, ".debug_line_str"))
            @intFromEnum(Dwarf.Section.Id.debug_line_str)
        else if (std.mem.eql(u8, name, ".debug_ranges"))
            @intFromEnum(Dwarf.Section.Id.debug_ranges)
        else if (std.mem.eql(u8, name, ".debug_loclists"))
            @intFromEnum(Dwarf.Section.Id.debug_loclists)
        else if (std.mem.eql(u8, name, ".debug_rnglists"))
            @intFromEnum(Dwarf.Section.Id.debug_rnglists)
        else if (std.mem.eql(u8, name, ".debug_addr"))
            @intFromEnum(Dwarf.Section.Id.debug_addr)
        else if (std.mem.eql(u8, name, ".debug_names"))
            @intFromEnum(Dwarf.Section.Id.debug_names)
        else if (std.mem.eql(u8, name, ".eh_frame"))
            @intFromEnum(Dwarf.Section.Id.eh_frame)
        else if (std.mem.eql(u8, name, ".eh_frame_hdr"))
            @intFromEnum(Dwarf.Section.Id.eh_frame_hdr)
        else
            null;

        if (dwarf_idx) |i| {
            dwarf.sections[i] = .{
                .data = bytes[shdr.sh_offset .. shdr.sh_offset + shdr.sh_size],
                .owned = false,
            };
        }
    }

    try dwarf.open(gpa);
    return dwarf;
}

fn getCStrAt(bytes: []const u8, offset: u64) ?[]const u8 {
    if (offset >= bytes.len) return null;
    const tail = bytes[offset..];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse return null;
    return tail[0..end];
}

// ── Objdump ─────────────────────────────────────────────────────────────────

fn runObjdump(gpa: Allocator, path: []const u8) ![]const u8 {
    var child = std.process.Child.init(
        &.{ "objdump", "-d", "-M", "intel", path },
        gpa,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const stdout = try child.stdout.?.readToEndAlloc(gpa, std.math.maxInt(u32));
    _ = try child.wait();

    return stdout;
}

// ── Disassembly parsing ─────────────────────────────────────────────────────

fn parseDisasm(
    gpa: Allocator,
    output: []const u8,
    lines: *std.ArrayList(DisasmLine),
    addr_map: *std.AutoHashMap(u64, usize),
) void {
    var iter = std.mem.splitScalar(u8, output, '\n');
    while (iter.next()) |line| {
        if (line.len == 0) continue;

        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (parseInstructionAddr(trimmed)) |addr| {
            const display = extractInstruction(gpa, trimmed, addr) catch line;
            if (display.len == 0) continue;
            const idx = lines.items.len;
            lines.append(gpa, .{
                .address = addr,
                .text = display,
                .is_label = false,
            }) catch continue;
            addr_map.put(addr, idx) catch {};
        } else if (isLabelLine(trimmed)) {
            lines.append(gpa, .{
                .address = 0,
                .text = extractLabel(trimmed),
                .is_label = true,
            }) catch continue;
        }
    }
}

fn extractInstruction(gpa: Allocator, line: []const u8, addr: u64) ![]const u8 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return line;
    const after_colon = line[colon + 1 ..];
    const first_tab = std.mem.indexOfScalar(u8, after_colon, '\t') orelse return "";
    const after_hex = after_colon[first_tab + 1 ..];
    const second_tab = std.mem.indexOfScalar(u8, after_hex, '\t') orelse return "";
    const instruction = std.mem.trimLeft(u8, after_hex[second_tab + 1 ..], " ");
    if (instruction.len == 0) return "";
    return std.fmt.allocPrint(gpa, "{x}: {s}", .{ addr, instruction });
}

fn extractLabel(line: []const u8) []const u8 {
    const open = std.mem.indexOfScalar(u8, line, '<') orelse return line;
    const close = std.mem.indexOfScalar(u8, line, '>') orelse return line;
    if (close > open) return line[open .. close + 1];
    return line;
}

fn parseInstructionAddr(line: []const u8) ?u64 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    if (colon == 0) return null;
    const hex = line[0..colon];
    for (hex) |c| {
        if (!std.ascii.isHex(c)) return null;
    }
    return std.fmt.parseInt(u64, hex, 16) catch null;
}

fn isLabelLine(line: []const u8) bool {
    if (line.len == 0) return false;
    return std.mem.endsWith(u8, line, ">:") or
        (line[0] != ' ' and std.mem.indexOfScalar(u8, line, '<') != null);
}

// ── Reverse map building ────────────────────────────────────────────────────

fn buildReverseMap(
    gpa: Allocator,
    dwarf: *Dwarf,
    addr_to_disasm: *std.AutoHashMap(u64, usize),
    file_paths: *std.ArrayList([]const u8),
    file_path_map: *std.StringHashMap(u32),
    reverse_map: *std.AutoHashMap(SourceKey, DisasmIdxList),
) !void {
    for (dwarf.compile_unit_list.items) |*cu| {
        dwarf.populateSrcLocCache(gpa, cu) catch continue;
        const slc = &(cu.src_loc_cache orelse continue);

        const keys = slc.line_table.keys();
        const values = slc.line_table.values();

        for (keys, values) |pc, entry| {
            if (entry.isInvalid()) continue;

            const file_index = entry.file -| @intFromBool(slc.version < 5);
            if (file_index >= slc.files.len) continue;
            const file_entry = &slc.files[file_index];
            if (file_entry.dir_index >= slc.directories.len) continue;
            const dir_name = slc.directories[file_entry.dir_index].path;
            const full_path = std.fs.path.join(gpa, &.{ dir_name, file_entry.path }) catch continue;

            const file_idx = file_path_map.get(full_path) orelse blk: {
                const idx: u32 = @intCast(file_paths.items.len);
                file_paths.append(gpa, full_path) catch continue;
                file_path_map.put(full_path, idx) catch continue;
                break :blk idx;
            };

            const disasm_idx = addr_to_disasm.get(pc) orelse continue;

            const key = SourceKey{ .file_idx = file_idx, .line = entry.line };
            const gop = reverse_map.getOrPut(key) catch continue;
            if (!gop.found_existing) {
                gop.value_ptr.* = .empty;
            }
            gop.value_ptr.append(gpa, disasm_idx) catch {};
        }
    }
}

// ── Source file loading ─────────────────────────────────────────────────────

fn loadSourceFile(app: *App, path: []const u8) ?[][]const u8 {
    if (app.source_cache.get(path)) |lines| return lines;

    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    const content = file.readToEndAlloc(app.allocator, std.math.maxInt(u32)) catch return null;

    var lines_list: std.ArrayList([]const u8) = .empty;
    var iter = std.mem.splitScalar(u8, content, '\n');
    while (iter.next()) |line| {
        lines_list.append(app.allocator, line) catch return null;
    }

    const lines = lines_list.toOwnedSlice(app.allocator) catch return null;
    app.source_cache.put(path, lines) catch {};
    return lines;
}

// ── Navigation ──────────────────────────────────────────────────────────────

fn setInitialView(app: *App) void {
    for (app.disasm_lines, 0..) |dl, i| {
        if (dl.is_label or dl.address == 0) continue;
        const cu = app.dwarf.findCompileUnit(dl.address) catch continue;
        const sloc = app.dwarf.getLineNumberInfo(app.allocator, cu, dl.address) catch continue;
        app.disasm_cursor = i;
        app.current_file = sloc.file_name;
        app.current_file_lines = loadSourceFile(app, sloc.file_name);
        if (sloc.line > 0) {
            app.src_cursor = @intCast(sloc.line - 1);
        }
        return;
    }
}

fn moveCursor(app: *App, delta: i32) void {
    const height: usize = @as(usize, app.term_h) -| 2;
    if (app.active_pane == .source) {
        const max = if (app.current_file_lines) |lines| lines.len else 1;
        if (max == 0) return;
        const new = @as(i64, @intCast(app.src_cursor)) + delta;
        app.src_cursor = @intCast(std.math.clamp(new, 0, @as(i64, @intCast(max -| 1))));
        ensureScroll(&app.src_scroll, app.src_cursor, height);
    } else {
        if (app.disasm_lines.len == 0) return;
        const new = @as(i64, @intCast(app.disasm_cursor)) + delta;
        app.disasm_cursor = @intCast(std.math.clamp(new, 0, @as(i64, @intCast(app.disasm_lines.len - 1))));
        ensureScroll(&app.disasm_scroll, app.disasm_cursor, height);
    }
}

fn updateHighlights(app: *App) !void {
    app.highlighted_disasm.clearRetainingCapacity();
    app.highlighted_source.clearRetainingCapacity();

    if (app.active_pane == .source) {
        if (app.current_file) |file| {
            const file_idx = resolveFileIdx(app, file);
            if (file_idx) |fi| {
                const key = SourceKey{ .file_idx = fi, .line = @intCast(app.src_cursor + 1) };
                if (app.reverse_map.get(key)) |indices| {
                    for (indices.items) |idx| {
                        try app.highlighted_disasm.put(idx, {});
                    }
                    if (indices.items.len > 0) {
                        autoScroll(&app.disasm_scroll, indices.items[0], app.term_h -| 2);
                    }
                }
            }
        }
    } else {
        if (app.disasm_cursor < app.disasm_lines.len) {
            const dl = app.disasm_lines[app.disasm_cursor];
            if (!dl.is_label and dl.address != 0) {
                const cu = app.dwarf.findCompileUnit(dl.address) catch return;
                const sloc = app.dwarf.getLineNumberInfo(app.allocator, cu, dl.address) catch return;

                if (app.current_file == null or !std.mem.eql(u8, app.current_file.?, sloc.file_name)) {
                    app.current_file = sloc.file_name;
                    app.current_file_lines = loadSourceFile(app, sloc.file_name);
                }

                if (sloc.line > 0) {
                    const src_line: u32 = @intCast(sloc.line);
                    try app.highlighted_source.put(src_line, {});
                    autoScroll(&app.src_scroll, src_line -| 1, app.term_h -| 2);
                }
            }
        }
    }
}

fn resolveFileIdx(app: *App, file: []const u8) ?u32 {
    if (app.file_path_map.get(file)) |idx| return idx;
    const basename = std.fs.path.basename(file);
    for (app.file_paths.items, 0..) |path, i| {
        if (std.mem.endsWith(u8, path, basename)) return @intCast(i);
    }
    return null;
}

fn pushNav(app: *App) void {
    app.nav_stack.append(app.allocator, .{
        .file = app.current_file,
        .src_cursor = app.src_cursor,
        .src_col = app.src_col,
        .src_scroll = app.src_scroll,
        .disasm_cursor = app.disasm_cursor,
        .disasm_col = app.disasm_col,
        .disasm_scroll = app.disasm_scroll,
        .active_pane = app.active_pane,
    }) catch {};
}

fn goBack(app: *App) void {
    const entry = app.nav_stack.pop() orelse return;
    app.current_file = entry.file;
    app.current_file_lines = if (entry.file) |f| loadSourceFile(app, f) else null;
    app.src_cursor = entry.src_cursor;
    app.src_col = entry.src_col;
    app.src_scroll = entry.src_scroll;
    app.disasm_cursor = entry.disasm_cursor;
    app.disasm_col = entry.disasm_col;
    app.disasm_scroll = entry.disasm_scroll;
    app.active_pane = entry.active_pane;
}

fn goToDefinition(app: *App) void {
    if (app.active_pane == .disasm) {
        goToDefDisasm(app);
    } else {
        goToDefSource(app);
    }
}

fn goToDefDisasm(app: *App) void {
    if (app.disasm_cursor >= app.disasm_lines.len) return;
    const dl = app.disasm_lines[app.disasm_cursor];
    if (dl.is_label) return;

    // Look for "call" or "jmp" instruction, extract target address
    // Format: "addr: call target_addr <func>"
    const text = dl.text;
    const colon_space = std.mem.indexOf(u8, text, ": ") orelse return;
    const instr = text[colon_space + 2 ..];

    // Check if it's a call or jmp
    const is_call = std.mem.startsWith(u8, instr, "call ");
    const is_jmp = std.mem.startsWith(u8, instr, "jmp ");
    if (!is_call and !is_jmp) return;

    const skip = if (is_call) @as(usize, 5) else 4;
    const operand = std.mem.trimLeft(u8, instr[skip..], " ");

    // Try to parse the target as a hex address (objdump resolves direct calls)
    const target_addr = parseHexAddr(operand) orelse return;

    // Find in disasm
    const target_idx = app.addr_to_disasm.get(target_addr) orelse return;

    // Push current position
    pushNav(app);

    // Jump
    app.disasm_cursor = target_idx;
    app.disasm_col = 0;
    const height: usize = @as(usize, app.term_h) -| 2;
    autoScroll(&app.disasm_scroll, target_idx, @intCast(height));
    ensureScroll(&app.disasm_scroll, app.disasm_cursor, height);

    // Update source to match
    if (target_idx < app.disasm_lines.len) {
        const target_dl = app.disasm_lines[target_idx];
        if (!target_dl.is_label and target_dl.address != 0) {
            const cu = app.dwarf.findCompileUnit(target_dl.address) catch return;
            const sloc = app.dwarf.getLineNumberInfo(app.allocator, cu, target_dl.address) catch return;
            app.current_file = sloc.file_name;
            app.current_file_lines = loadSourceFile(app, sloc.file_name);
            if (sloc.line > 0) {
                app.src_cursor = @intCast(sloc.line - 1);
                app.src_col = 0;
            }
        }
    }
}

fn goToDefSource(app: *App) void {
    // Extract word under cursor
    const word = wordUnderCursor(app) orelse return;

    // Search disasm labels for a matching function name
    for (app.disasm_lines, 0..) |dl, i| {
        if (!dl.is_label) continue;
        // Labels look like "<func_name>" — check if the label contains the word
        if (std.mem.indexOf(u8, dl.text, word) != null) {
            // Found! The label itself has address 0, but the next line should be the first instruction
            pushNav(app);
            const target = if (i + 1 < app.disasm_lines.len and !app.disasm_lines[i + 1].is_label)
                i + 1
            else
                i;
            app.disasm_cursor = target;
            app.disasm_col = 0;
            app.active_pane = .disasm;
            const height: usize = @as(usize, app.term_h) -| 2;
            autoScroll(&app.disasm_scroll, target, @intCast(height));
            ensureScroll(&app.disasm_scroll, app.disasm_cursor, height);

            // Update source pane to the target function's source
            if (target < app.disasm_lines.len) {
                const target_dl = app.disasm_lines[target];
                if (!target_dl.is_label and target_dl.address != 0) {
                    const cu = app.dwarf.findCompileUnit(target_dl.address) catch return;
                    const sloc = app.dwarf.getLineNumberInfo(app.allocator, cu, target_dl.address) catch return;
                    app.current_file = sloc.file_name;
                    app.current_file_lines = loadSourceFile(app, sloc.file_name);
                    if (sloc.line > 0) {
                        app.src_cursor = @intCast(sloc.line - 1);
                        app.src_col = 0;
                    }
                }
            }
            return;
        }
    }
}

fn wordUnderCursor(app: *App) ?[]const u8 {
    if (app.current_file_lines == null) return null;
    const lines = app.current_file_lines.?;
    if (app.src_cursor >= lines.len) return null;
    const line = lines[app.src_cursor];
    if (line.len == 0) return null;
    const col = @min(app.src_col, line.len -| 1);

    // Find word boundaries (identifier chars: alphanumeric + _)
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

fn wordForward(app: *App) void {
    const line = app.cursorLine();
    if (line.len == 0) return;
    var col = if (app.active_pane == .source) app.src_col else app.disasm_col;
    // Skip current word
    while (col < line.len and isIdentChar(line[col])) col += 1;
    // Skip whitespace/non-ident
    while (col < line.len and !isIdentChar(line[col])) col += 1;
    col = @min(col, line.len -| 1);
    if (app.active_pane == .source) app.src_col = col else app.disasm_col = col;
}

fn wordBackward(app: *App) void {
    const line = app.cursorLine();
    if (line.len == 0) return;
    var col = if (app.active_pane == .source) app.src_col else app.disasm_col;
    if (col == 0) return;
    col -= 1;
    // Skip whitespace/non-ident backwards
    while (col > 0 and !isIdentChar(line[col])) col -= 1;
    // Skip word backwards
    while (col > 0 and isIdentChar(line[col - 1])) col -= 1;
    if (app.active_pane == .source) app.src_col = col else app.disasm_col = col;
}

fn parseHexAddr(s: []const u8) ?u64 {
    // Parse hex until non-hex char (e.g. "ffffffff80001234 <func>")
    var end: usize = 0;
    // Skip optional 0x prefix
    const start: usize = if (s.len > 2 and s[0] == '0' and s[1] == 'x') 2 else 0;
    end = start;
    while (end < s.len and std.ascii.isHex(s[end])) end += 1;
    if (end == start) return null;
    return std.fmt.parseInt(u64, s[start..end], 16) catch null;
}

fn readPrompt(app: *App, prompt: []const u8) !?[]const u8 {
    var input: [256]u8 = undefined;
    var len: usize = 0;

    while (true) {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(app.allocator);
        const w = buf.writer(app.allocator);

        const total_w: usize = @as(usize, app.term_w);
        const status_row = app.term_h -| 1;
        try w.print("\x1b[{d};1H\x1b[7m{s}", .{ status_row, prompt });
        try w.writeAll(input[0..len]);
        const written = prompt.len + len;
        if (written < total_w) try padSpaces(w, total_w - written);
        try w.writeAll("\x1b[0m");
        try app.tty.writeAll(buf.items);

        var byte: [1]u8 = undefined;
        const n = try app.tty.read(&byte);
        if (n == 0) return null;

        switch (byte[0]) {
            '\n', '\r' => {
                if (len == 0) return null;
                return input[0..len];
            },
            0x1b => return null,
            0x7f, 0x08 => {
                len -|= 1;
            },
            else => {
                if (byte[0] >= 0x20 and len < input.len) {
                    input[len] = byte[0];
                    len += 1;
                }
            },
        }
    }
}

fn gotoFile(app: *App, query: []const u8) void {
    var match: ?[]const u8 = null;
    for (app.file_paths.items) |path| {
        if (std.mem.indexOf(u8, path, query) != null) {
            match = path;
            break;
        }
    }

    const target_path = match orelse return;

    app.current_file = target_path;
    app.current_file_lines = loadSourceFile(app, target_path);
    app.src_cursor = 0;
    app.src_col = 0;
    app.src_scroll = 0;
    app.active_pane = .source;

    const file_idx = app.file_path_map.get(target_path) orelse return;

    var best_disasm_idx: ?usize = null;
    var best_line: u32 = std.math.maxInt(u32);

    var iter = app.reverse_map.iterator();
    while (iter.next()) |entry| {
        if (entry.key_ptr.file_idx == file_idx) {
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

    if (best_disasm_idx) |idx| {
        app.disasm_cursor = idx;
        app.disasm_scroll = idx;
    }
    if (best_line != std.math.maxInt(u32) and best_line > 0) {
        app.src_cursor = best_line - 1;
    }
}

fn autoScroll(scroll: *usize, target: usize, visible_height: u16) void {
    const h = @as(usize, visible_height);
    if (h == 0) return;
    scroll.* = target -| (h / 2);
}

// ── Input ───────────────────────────────────────────────────────────────────

const Action = enum {
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

fn readInput(tty: std.fs.File) !Action {
    var buf: [1]u8 = undefined;
    const n = try tty.read(&buf);
    if (n == 0) return .quit;

    return switch (buf[0]) {
        'q', 0x03 => .quit,
        'j' => .down,
        'k' => .up,
        'h' => .left,
        'l' => .right,
        '\t' => .tab,
        '/' => .goto_file,
        'w' => .word_forward,
        'b' => .word_backward,
        '0' => .line_start,
        '$' => .line_end,
        'g' => readGCommand(tty),
        0x04 => .half_page_down,
        0x15 => .half_page_up,
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

// ── Syntax Highlighting ────────────────────────────────────────────────────

const SyntaxColor = enum(u8) {
    default,
    keyword,
    string,
    number,
    comment,
    builtin,
    type_ident,
    asm_address,
    asm_mnemonic,
    asm_register,
    asm_immediate,
    asm_label,

    fn escape(c: SyntaxColor) []const u8 {
        return switch (c) {
            .default => "",
            .keyword => "\x1b[38;5;168m",
            .string => "\x1b[38;5;107m",
            .number => "\x1b[38;5;173m",
            .comment => "\x1b[38;5;243m",
            .builtin => "\x1b[38;5;109m",
            .type_ident => "\x1b[38;5;180m",
            .asm_address => "\x1b[38;5;243m",
            .asm_mnemonic => "\x1b[38;5;75m",
            .asm_register => "\x1b[38;5;114m",
            .asm_immediate => "\x1b[38;5;173m",
            .asm_label => "\x1b[38;5;223m",
        };
    }
};

fn highlightZigLine(line: []const u8, colors: []SyntaxColor) void {
    @memset(colors[0..line.len], .default);
    var buf: [4096]u8 = undefined;
    if (line.len >= buf.len) return;
    @memcpy(buf[0..line.len], line);
    buf[line.len] = 0;
    const z_line: [:0]const u8 = buf[0..line.len :0];

    var tok = std.zig.Tokenizer.init(z_line);
    var prev_end: usize = 0;

    while (true) {
        const token = tok.next();
        if (token.tag == .eof) break;

        // Gaps between tokens may contain // comments (tokenizer skips them)
        if (token.loc.start > prev_end) {
            const gap = z_line[prev_end..token.loc.start];
            if (std.mem.indexOf(u8, gap, "//")) |offset| {
                @memset(colors[prev_end + offset .. line.len], .comment);
                return;
            }
        }

        const color = classifyZigToken(token.tag, z_line[token.loc.start..token.loc.end]);
        @memset(colors[token.loc.start..token.loc.end], color);
        prev_end = token.loc.end;
    }

    // Trailing comment after last token
    if (prev_end < line.len) {
        const gap = z_line[prev_end..line.len];
        if (std.mem.indexOf(u8, gap, "//")) |offset| {
            @memset(colors[prev_end + offset .. line.len], .comment);
        }
    }
}

fn classifyZigToken(tag: std.zig.Token.Tag, text: []const u8) SyntaxColor {
    return switch (tag) {
        .string_literal, .multiline_string_literal_line, .char_literal => .string,
        .number_literal => .number,
        .builtin => .builtin,
        .doc_comment, .container_doc_comment => .comment,
        .identifier => classifyIdentifier(text),
        else => if (isKeywordTag(tag)) .keyword else .default,
    };
}

fn isKeywordTag(tag: std.zig.Token.Tag) bool {
    const t = @intFromEnum(tag);
    return t >= @intFromEnum(std.zig.Token.Tag.keyword_addrspace) and
        t <= @intFromEnum(std.zig.Token.Tag.keyword_while);
}

fn classifyIdentifier(text: []const u8) SyntaxColor {
    if (text.len == 0) return .default;
    if (std.zig.primitives.isPrimitive(text)) return .type_ident;
    if (text[0] >= 'A' and text[0] <= 'Z') return .type_ident;
    return .default;
}

fn highlightDisasm(text: []const u8, is_label: bool, colors: []SyntaxColor) void {
    @memset(colors[0..text.len], .default);
    if (is_label) {
        @memset(colors[0..text.len], .asm_label);
        return;
    }

    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return;
    @memset(colors[0 .. colon + 1], .asm_address);

    var pos = colon + 1;
    while (pos < text.len and text[pos] == ' ') : (pos += 1) {}

    // Mnemonic
    const mn_start = pos;
    while (pos < text.len and text[pos] != ' ') : (pos += 1) {}
    if (mn_start < pos) @memset(colors[mn_start..pos], .asm_mnemonic);

    // Operands
    while (pos < text.len) {
        if (text[pos] == '<') {
            const end = std.mem.indexOfScalarPos(u8, text, pos + 1, '>') orelse text.len - 1;
            @memset(colors[pos .. end + 1], .asm_label);
            pos = end + 1;
        } else if (text[pos] == '0' and pos + 1 < text.len and text[pos + 1] == 'x') {
            const s = pos;
            pos += 2;
            while (pos < text.len and std.ascii.isHex(text[pos])) : (pos += 1) {}
            @memset(colors[s..pos], .asm_immediate);
        } else if (std.ascii.isAlphabetic(text[pos])) {
            const s = pos;
            while (pos < text.len and (std.ascii.isAlphanumeric(text[pos]) or text[pos] == '_')) : (pos += 1) {}
            if (isX86Register(text[s..pos])) @memset(colors[s..pos], .asm_register);
        } else {
            pos += 1;
        }
    }
}

fn isX86Register(name: []const u8) bool {
    const regs = std.StaticStringMap(void).initComptime(.{
        .{ "rax", {} }, .{ "rbx", {} }, .{ "rcx", {} }, .{ "rdx", {} },
        .{ "rsi", {} }, .{ "rdi", {} }, .{ "rsp", {} }, .{ "rbp", {} },
        .{ "r8", {} },  .{ "r9", {} },  .{ "r10", {} }, .{ "r11", {} },
        .{ "r12", {} }, .{ "r13", {} }, .{ "r14", {} }, .{ "r15", {} },
        .{ "eax", {} }, .{ "ebx", {} }, .{ "ecx", {} }, .{ "edx", {} },
        .{ "esi", {} }, .{ "edi", {} }, .{ "esp", {} }, .{ "ebp", {} },
        .{ "ax", {} },  .{ "bx", {} },  .{ "cx", {} },  .{ "dx", {} },
        .{ "si", {} },  .{ "di", {} },  .{ "sp", {} },  .{ "bp", {} },
        .{ "al", {} },  .{ "bl", {} },  .{ "cl", {} },  .{ "dl", {} },
        .{ "ah", {} },  .{ "bh", {} },  .{ "ch", {} },  .{ "dh", {} },
        .{ "sil", {} }, .{ "dil", {} }, .{ "spl", {} }, .{ "bpl", {} },
        .{ "r8b", {} }, .{ "r9b", {} }, .{ "r10b", {} }, .{ "r11b", {} },
        .{ "r12b", {} }, .{ "r13b", {} }, .{ "r14b", {} }, .{ "r15b", {} },
        .{ "r8w", {} }, .{ "r9w", {} }, .{ "r10w", {} }, .{ "r11w", {} },
        .{ "r12w", {} }, .{ "r13w", {} }, .{ "r14w", {} }, .{ "r15w", {} },
        .{ "r8d", {} }, .{ "r9d", {} }, .{ "r10d", {} }, .{ "r11d", {} },
        .{ "r12d", {} }, .{ "r13d", {} }, .{ "r14d", {} }, .{ "r15d", {} },
        .{ "xmm0", {} }, .{ "xmm1", {} }, .{ "xmm2", {} }, .{ "xmm3", {} },
        .{ "xmm4", {} }, .{ "xmm5", {} }, .{ "xmm6", {} }, .{ "xmm7", {} },
        .{ "xmm8", {} }, .{ "xmm9", {} }, .{ "xmm10", {} }, .{ "xmm11", {} },
        .{ "xmm12", {} }, .{ "xmm13", {} }, .{ "xmm14", {} }, .{ "xmm15", {} },
        .{ "cs", {} },  .{ "ds", {} },  .{ "es", {} },  .{ "fs", {} },
        .{ "gs", {} },  .{ "ss", {} },  .{ "rip", {} }, .{ "eip", {} },
        .{ "cr0", {} }, .{ "cr2", {} }, .{ "cr3", {} }, .{ "cr4", {} },
    });
    return regs.has(name);
}

fn writeColoredText(w: anytype, text: []const u8, colors: []const SyntaxColor) !void {
    var current: SyntaxColor = .default;
    for (text, colors) |byte, color| {
        if (color != current) {
            if (current != .default) try w.writeAll("\x1b[39m");
            if (color != .default) try w.writeAll(color.escape());
            current = color;
        }
        try w.writeByte(byte);
    }
    if (current != .default) try w.writeAll("\x1b[39m");
}

fn renderWithCharCursorColored(w: anytype, text: []const u8, colors: []const SyntaxColor, col: usize) !void {
    if (text.len == 0) return;
    const cursor_pos = @min(col, text.len);

    if (cursor_pos > 0)
        try writeColoredText(w, text[0..cursor_pos], colors[0..cursor_pos]);

    if (cursor_pos < text.len) {
        const c = colors[cursor_pos];
        if (c != .default) try w.writeAll(c.escape());
        try w.writeAll("\x1b[7m");
        try w.writeByte(text[cursor_pos]);
        try w.writeAll("\x1b[27m\x1b[48;5;236m");
        if (c != .default) try w.writeAll("\x1b[39m");

        if (cursor_pos + 1 < text.len)
            try writeColoredText(w, text[cursor_pos + 1 ..], colors[cursor_pos + 1 ..]);
    }
}

// ── Rendering ───────────────────────────────────────────────────────────────

fn render(app: *App) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(app.allocator);
    const w = buf.writer(app.allocator);

    try w.writeAll("\x1b[H");

    const height: usize = @as(usize, app.term_h) -| 2;
    const total_w: usize = @as(usize, app.term_w);
    const left_w = total_w / 2 -| 1;
    const right_w = total_w -| left_w -| 1;

    if (app.active_pane == .source) {
        ensureScroll(&app.src_scroll, app.src_cursor, height);
    } else {
        ensureScroll(&app.disasm_scroll, app.disasm_cursor, height);
    }

    for (0..height) |row| {
        const src_line_idx = app.src_scroll + row;
        try renderSourceLine(w, app, src_line_idx, left_w);

        try w.writeAll("\x1b[90m\xe2\x94\x82\x1b[0m");

        const disasm_line_idx = app.disasm_scroll + row;
        try renderDisasmLine(w, app, disasm_line_idx, right_w);

        try w.writeAll("\x1b[K\n");
    }

    try w.writeAll("\x1b[7m");
    try renderStatusBar(w, app, total_w);
    try w.writeAll("\x1b[0m\x1b[K");

    try app.tty.writeAll(buf.items);
}

fn renderSourceLine(w: anytype, app: *App, line_idx: usize, width: usize) !void {
    const is_cursor_line = (app.active_pane == .source and line_idx == app.src_cursor);
    const line_num: u32 = @intCast(line_idx + 1);
    const is_highlighted = app.highlighted_source.contains(line_num);

    if (app.current_file_lines) |lines| {
        if (line_idx < lines.len) {
            const num_w: usize = 6;
            const content_w = width -| num_w;
            const line = lines[line_idx];
            const start = @min(app.src_hscroll, line.len);
            const visible = line[start..];
            const to_write = @min(visible.len, content_w);

            var color_buf: [4096]SyntaxColor = undefined;
            if (line.len < color_buf.len) {
                highlightZigLine(line, color_buf[0..line.len]);
            } else {
                @memset(color_buf[0..@min(line.len, color_buf.len)], .default);
            }
            const vis_colors = color_buf[start..][0..to_write];

            if (is_cursor_line) {
                try w.writeAll("\x1b[48;5;236m");
                try w.print("{d:>5} ", .{line_num});
                try renderWithCharCursorColored(w, visible[0..to_write], vis_colors, app.src_col -| start);
                const written = num_w + to_write;
                if (written < width) try padSpaces(w, width - written);
                try w.writeAll("\x1b[0m");
            } else if (is_highlighted) {
                try w.writeAll("\x1b[43;30m");
                try w.print("{d:>5} ", .{line_num});
                try w.writeAll(visible[0..to_write]);
                const written = num_w + to_write;
                if (written < width) try padSpaces(w, width - written);
                try w.writeAll("\x1b[0m");
            } else {
                try w.print("{d:>5} ", .{line_num});
                try writeColoredText(w, visible[0..to_write], vis_colors);
                const written = num_w + to_write;
                if (written < width) try padSpaces(w, width - written);
            }
        } else {
            try w.writeAll("\x1b[90m~\x1b[0m");
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

fn renderDisasmLine(w: anytype, app: *App, line_idx: usize, width: usize) !void {
    const is_cursor_line = (app.active_pane == .disasm and line_idx == app.disasm_cursor);
    const is_highlighted = app.highlighted_disasm.contains(line_idx);

    if (line_idx < app.disasm_lines.len) {
        const dl = app.disasm_lines[line_idx];
        const text = dl.text;
        const start = @min(app.disasm_hscroll, text.len);
        const visible = text[start..];
        const to_write = @min(visible.len, width);

        var color_buf: [4096]SyntaxColor = undefined;
        if (text.len < color_buf.len) {
            highlightDisasm(text, dl.is_label, color_buf[0..text.len]);
        } else {
            @memset(color_buf[0..@min(text.len, color_buf.len)], .default);
        }
        const vis_colors = color_buf[start..][0..to_write];

        if (is_cursor_line) {
            try w.writeAll("\x1b[48;5;236m");
            try renderWithCharCursorColored(w, visible[0..to_write], vis_colors, app.disasm_col -| start);
            if (to_write < width) try padSpaces(w, width - to_write);
            try w.writeAll("\x1b[0m");
        } else if (is_highlighted) {
            try w.writeAll("\x1b[43;30m");
            try w.writeAll(visible[0..to_write]);
            if (to_write < width) try padSpaces(w, width - to_write);
            try w.writeAll("\x1b[0m");
        } else {
            try writeColoredText(w, visible[0..to_write], vis_colors);
            if (to_write < width) try padSpaces(w, width - to_write);
        }
    } else {
        try padSpaces(w, width);
    }
}

fn renderStatusBar(w: anytype, app: *App, width: usize) !void {
    var status_buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&status_buf);
    const sw = fbs.writer();

    const file_name = if (app.current_file) |f| std.fs.path.basename(f) else "<none>";
    const src_line = app.src_cursor + 1;
    const src_col_display = app.src_col + 1;

    if (app.disasm_cursor < app.disasm_lines.len) {
        const dl = app.disasm_lines[app.disasm_cursor];
        sw.print(" {s}:{d}:{d}  |  0x{x}  |  {s}  |  gd=def gb=back /=file", .{
            file_name,
            src_line,
            src_col_display,
            dl.address,
            if (app.active_pane == .source) "SRC" else "ASM",
        }) catch {};
    } else {
        sw.print(" {s}:{d}:{d}  |  {s}  |  gd=def gb=back /=file", .{
            file_name,
            src_line,
            src_col_display,
            if (app.active_pane == .source) "SRC" else "ASM",
        }) catch {};
    }

    const status = fbs.getWritten();
    const to_write = @min(status.len, width);
    try w.writeAll(status[0..to_write]);
    if (to_write < width) try padSpaces(w, width - to_write);
}

fn padSpaces(w: anytype, count: usize) !void {
    const spaces = "                                                                                ";
    var remaining = count;
    while (remaining > 0) {
        const chunk = @min(remaining, spaces.len);
        try w.writeAll(spaces[0..chunk]);
        remaining -= chunk;
    }
}

fn ensureScroll(scroll: *usize, cursor: usize, visible: usize) void {
    if (visible == 0) return;
    const margin = @min(3, visible / 4);
    if (cursor < scroll.* + margin) {
        scroll.* = cursor -| margin;
    } else if (cursor + margin >= scroll.* + visible) {
        scroll.* = (cursor + margin + 1) -| visible;
    }
}

// ── Terminal ────────────────────────────────────────────────────────────────

fn enableRawMode(fd: std.posix.fd_t, orig: std.posix.termios) void {
    var raw = orig;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    raw.lflag.ISIG = false;
    raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
    raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;
    std.posix.tcsetattr(fd, .FLUSH, raw) catch {};
}

const WinSize = struct { rows: u16, cols: u16 };

fn getWinSize(fd: std.posix.fd_t) WinSize {
    var ws: std.posix.winsize = undefined;
    const rc = std.posix.system.ioctl(fd, std.posix.T.IOCGWINSZ, @intFromPtr(&ws));
    if (rc == 0) {
        return .{ .rows = ws.row, .cols = ws.col };
    }
    return .{ .rows = 24, .cols = 80 };
}
