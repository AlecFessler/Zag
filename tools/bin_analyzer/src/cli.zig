const std = @import("std");
const debug_info = @import("debug_info.zig");
const disasm_mod = @import("disasm.zig");

const Allocator = std.mem.Allocator;
const Dwarf = std.debug.Dwarf;
const SourceKey = debug_info.SourceKey;
const DisasmIdxList = debug_info.DisasmIdxList;
const DisasmLine = disasm_mod.DisasmLine;

pub const CliQuery = enum { none, list_files, source, disasm, func, dump_map };

pub const usage_text =
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

pub fn cliMode(
    gpa: Allocator,
    query: CliQuery,
    query_arg: ?[]const u8,
    context_lines: usize,
    dwarf: *Dwarf,
    disasm_lines: []DisasmLine,
    addr_to_disasm: *std.AutoHashMap(u64, usize),
    file_paths: *std.ArrayList([]const u8),
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
            try cliSource(gpa, w, arg, context_lines, dwarf, disasm_lines, file_paths, reverse_map);
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
        .dump_map => {
            const arg = query_arg orelse "main.zig";
            // Exact same logic as gotoFile: find path in file_paths, resolveFileIdx, scan reverse_map
            var match: ?[]const u8 = null;
            for (file_paths.items) |path| {
                if (std.mem.indexOf(u8, path, arg) != null) {
                    match = path;
                    break;
                }
            }
            const target_path = match orelse {
                try w.print("No file matching '{s}'\n", .{arg});
                return;
            };
            const file_idx = debug_info.resolveFileIdx(file_paths, target_path) orelse {
                try w.print("resolveFileIdx returned null for '{s}'\n", .{target_path});
                return;
            };
            try w.print("target='{s}' file_idx={d}\n", .{ target_path, file_idx });

            // Now scan reverse_map exactly like gotoFile does
            var best_line: u32 = std.math.maxInt(u32);
            var count: usize = 0;
            var rm_iter = reverse_map.iterator();
            while (rm_iter.next()) |entry| {
                if (entry.key_ptr.file_idx == file_idx) {
                    count += 1;
                    if (entry.key_ptr.line < best_line) best_line = entry.key_ptr.line;
                }
            }
            try w.print("reverse_map entries with file_idx={d}: {d}, min_line={d}\n", .{ file_idx, count, best_line });

            // Also check what --source would use
            const cli_file_idx = debug_info.resolveFileIdx(file_paths, target_path);
            try w.print("CLI resolveFileIdx={any}\n", .{cli_file_idx});

            // Check a few specific lines
            for ([_]u32{ 14, 15, 17, 20, 62, 65 }) |ln| {
                const key = SourceKey{ .file_idx = file_idx, .line = ln };
                if (reverse_map.get(key)) |indices| {
                    try w.print("  line {d}: {d} disasm entries\n", .{ ln, indices.items.len });
                } else {
                    try w.print("  line {d}: NOT FOUND\n", .{ln});
                }
            }
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
    reverse_map: *std.AutoHashMap(SourceKey, DisasmIdxList),
) !void {
    const colon = std.mem.lastIndexOfScalar(u8, arg, ':');
    const file_query = if (colon) |c| arg[0..c] else arg;
    const target_line: ?u32 = if (colon) |c| std.fmt.parseInt(u32, arg[c + 1 ..], 10) catch null else null;

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

    const source = debug_info.loadSourceFile(gpa, file_path);
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

    const file_idx = debug_info.resolveFileIdx(file_paths, file_path) orelse return;
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
    const addr = disasm_mod.parseHexAddr(arg) orelse {
        try w.print("Error: cannot parse address '{s}'\n", .{arg});
        return;
    };

    const idx = addr_to_disasm.get(addr) orelse blk: {
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

    try w.print("── Disassembly around 0x{x} ──\n\n", .{addr});
    const start = idx -| context_lines;
    const end = @min(idx + context_lines + 1, disasm_lines.len);
    for (start..end) |di| {
        const marker: u8 = if (di == idx) '>' else ' ';
        try w.print("  {c} {s}\n", .{ marker, disasm_lines[di].text });
    }

    if (idx < disasm_lines.len) {
        const dl = disasm_lines[idx];
        if (!dl.is_label and dl.address != 0) {
            const cu = dwarf.findCompileUnit(dl.address) catch return;
            const sloc = dwarf.getLineNumberInfo(gpa, cu, dl.address) catch return;
            try w.print("\n── Source: {s}:{d} ──\n\n", .{ sloc.file_name, sloc.line });

            if (debug_info.loadSourceFile(gpa, sloc.file_name)) |lines| {
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
    var found = false;
    for (disasm_lines, 0..) |dl, di| {
        if (!dl.is_label) continue;
        if (std.mem.indexOf(u8, dl.text, name) == null) continue;

        found = true;
        try w.print("── {s} ──\n\n", .{dl.text});

        try w.writeAll("Disassembly:\n");
        var count: usize = 0;
        var ii = di + 1;
        while (ii < disasm_lines.len and count < context_lines * 2 + 10) : (ii += 1) {
            if (disasm_lines[ii].is_label) break;
            try w.print("  {s}\n", .{disasm_lines[ii].text});
            count += 1;
        }

        if (di + 1 < disasm_lines.len) {
            const first_instr = disasm_lines[di + 1];
            if (!first_instr.is_label and first_instr.address != 0) {
                const cu = dwarf.findCompileUnit(first_instr.address) catch continue;
                const sloc = dwarf.getLineNumberInfo(gpa, cu, first_instr.address) catch continue;
                try w.print("\nDefined at: {s}:{d}\n", .{ sloc.file_name, sloc.line });

                if (debug_info.loadSourceFile(gpa, sloc.file_name)) |lines| {
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
