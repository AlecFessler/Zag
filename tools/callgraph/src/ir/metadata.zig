// LLVM IR metadata table.
//
// Holds the subset of !DI* records the call-graph parser cares about:
//   - DIFile      ! filename + directory
//   - DISubprogram   linkageName + file ref + line
//   - DILocation     line/col + scope ref
//   - DILexicalBlock scope chain (we only need scope-of-scope)
//
// All records are addressed by their numeric id (the `N` in `!N = ...`).
// Any other metadata kind is collected as `.other` so unknown refs in scope
// chains don't blow up — they just resolve to nothing.
//
// Strings are stored as slices into the original IR buffer. Resolution of
// scope chains is done by the consumer (parse.zig) via repeated lookups.

const std = @import("std");

pub const RecordKind = enum {
    file,
    subprogram,
    location,
    lexical_block,
    other,
};

pub const FileRecord = struct {
    filename: []const u8,
    directory: []const u8,
};

pub const SubprogramRecord = struct {
    name: ?[]const u8 = null,
    linkage_name: ?[]const u8 = null,
    file: ?u32 = null,
    line: u32 = 0,
};

pub const LocationRecord = struct {
    line: u32 = 0,
    column: u32 = 0,
    scope: ?u32 = null,
};

pub const LexicalBlockRecord = struct {
    scope: ?u32 = null,
    file: ?u32 = null,
};

pub const Record = union(RecordKind) {
    file: FileRecord,
    subprogram: SubprogramRecord,
    location: LocationRecord,
    lexical_block: LexicalBlockRecord,
    other: void,
};

pub const Table = struct {
    /// Sparse map: metadata id -> record.
    map: std.AutoHashMap(u32, Record),

    pub fn init(allocator: std.mem.Allocator) Table {
        return .{ .map = std.AutoHashMap(u32, Record).init(allocator) };
    }

    pub fn put(self: *Table, id: u32, rec: Record) !void {
        try self.map.put(id, rec);
    }

    pub fn get(self: *const Table, id: u32) ?Record {
        return self.map.get(id);
    }

    /// Walk a scope chain (DILocation.scope -> DILexicalBlock.scope -> ...)
    /// until a DISubprogram is reached. Returns its id, or null if the chain
    /// terminates without one (or loops).
    pub fn resolveSubprogram(self: *const Table, start: u32) ?u32 {
        var cur: u32 = start;
        var hops: u32 = 0;
        while (hops < 64) : (hops += 1) {
            const rec = self.get(cur) orelse return null;
            switch (rec) {
                .subprogram => return cur,
                .lexical_block => |lb| {
                    cur = lb.scope orelse return null;
                },
                .location => |loc| {
                    cur = loc.scope orelse return null;
                },
                else => return null,
            }
        }
        return null;
    }
};

/// Parse a metadata definition line like:
///
///   !4213 = distinct !DISubprogram(name: "...", linkageName: "...", file: !9, line: 161, ...)
///   !9 = !DIFile(filename: "ubsan_rt.zig", directory: "/usr/lib/zig")
///   !4243 = !DILocation(line: 165, column: 33, scope: !4213)
///
/// On success returns the id and the parsed Record. Returns null for lines we
/// don't recognise (e.g. plain tuples, DIBasicType, etc.) — caller skips them.
pub fn parseRecordLine(line: []const u8) ?struct { id: u32, rec: Record } {
    if (line.len < 3 or line[0] != '!') return null;

    // id ends at first space
    var i: usize = 1;
    while (i < line.len and line[i] != ' ') : (i += 1) {}
    const id = std.fmt.parseInt(u32, line[1..i], 10) catch return null;

    // expect " = "
    if (i + 3 > line.len) return null;
    if (!std.mem.startsWith(u8, line[i..], " = ")) return null;
    i += 3;

    // optional "distinct "
    if (std.mem.startsWith(u8, line[i..], "distinct ")) i += "distinct ".len;

    if (i >= line.len or line[i] != '!') return null;
    // record kind: !DISubprogram, !DIFile, etc., terminated by '('
    var j = i + 1;
    while (j < line.len and line[j] != '(' and line[j] != ' ') : (j += 1) {}
    const kind_name = line[i + 1 .. j];

    if (j >= line.len or line[j] != '(') {
        // tuple or anonymous — record as .other so scope walks abort cleanly
        return .{ .id = id, .rec = .{ .other = {} } };
    }

    // body: between matching ( ... ) — for our records there's exactly one
    // outer pair on the line, but values can contain nested parens (e.g.
    // DIFlags or expressions). Use depth tracking to find the close.
    const body_start = j + 1;
    var depth: u32 = 1;
    var in_str = false;
    var k = body_start;
    while (k < line.len) : (k += 1) {
        const c = line[k];
        if (in_str) {
            if (c == '\\' and k + 1 < line.len) {
                k += 1;
                continue;
            }
            if (c == '"') in_str = false;
            continue;
        }
        switch (c) {
            '"' => in_str = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if (depth == 0) break;
            },
            else => {},
        }
    }
    const body = if (k <= line.len) line[body_start..@min(k, line.len)] else line[body_start..];

    if (std.mem.eql(u8, kind_name, "DIFile")) {
        const filename = fieldString(body, "filename") orelse "";
        const directory = fieldString(body, "directory") orelse "";
        return .{ .id = id, .rec = .{ .file = .{ .filename = filename, .directory = directory } } };
    } else if (std.mem.eql(u8, kind_name, "DISubprogram")) {
        return .{ .id = id, .rec = .{ .subprogram = .{
            .name = fieldString(body, "name"),
            .linkage_name = fieldString(body, "linkageName"),
            .file = fieldMetaRef(body, "file"),
            .line = fieldInt(body, "line") orelse 0,
        } } };
    } else if (std.mem.eql(u8, kind_name, "DILocation")) {
        return .{ .id = id, .rec = .{ .location = .{
            .line = fieldInt(body, "line") orelse 0,
            .column = fieldInt(body, "column") orelse 0,
            .scope = fieldMetaRef(body, "scope"),
        } } };
    } else if (std.mem.eql(u8, kind_name, "DILexicalBlock") or std.mem.eql(u8, kind_name, "DILexicalBlockFile")) {
        return .{ .id = id, .rec = .{ .lexical_block = .{
            .scope = fieldMetaRef(body, "scope"),
            .file = fieldMetaRef(body, "file"),
        } } };
    }

    return .{ .id = id, .rec = .{ .other = {} } };
}

/// Find `key:` at the start of a field within an !DI...(body) record.
/// Returns the slice starting *after* the ": " of the matching field, or null.
///
/// Scans for ", key: " or "(key: " (or starts-with "key: " when offset == 0).
/// Only matches at top level (paren depth 0), so nested DIExpression(...) etc.
/// can't false-match.
fn findField(body: []const u8, key: []const u8) ?usize {
    var depth: u32 = 0;
    var in_str = false;
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        const c = body[i];
        if (in_str) {
            if (c == '\\' and i + 1 < body.len) {
                i += 1;
                continue;
            }
            if (c == '"') in_str = false;
            continue;
        }
        switch (c) {
            '"' => in_str = true,
            '(' => depth += 1,
            ')' => if (depth > 0) {
                depth -= 1;
            },
            else => {},
        }
        if (depth != 0) continue;
        // candidate start: i==0 or after ", "
        const at_start = (i == 0) or (i >= 2 and body[i - 2] == ',' and body[i - 1] == ' ');
        if (!at_start) continue;
        if (i + key.len + 2 > body.len) return null;
        if (!std.mem.eql(u8, body[i .. i + key.len], key)) continue;
        if (body[i + key.len] != ':' or body[i + key.len + 1] != ' ') continue;
        return i + key.len + 2;
    }
    return null;
}

/// Read a `key: "value"` string field. Strips the quotes; does NOT unescape.
fn fieldString(body: []const u8, key: []const u8) ?[]const u8 {
    const start = findField(body, key) orelse return null;
    if (start >= body.len or body[start] != '"') return null;
    var i: usize = start + 1;
    while (i < body.len) : (i += 1) {
        const c = body[i];
        if (c == '\\' and i + 1 < body.len) {
            i += 1;
            continue;
        }
        if (c == '"') return body[start + 1 .. i];
    }
    return null;
}

/// Read a `key: 123` integer field.
fn fieldInt(body: []const u8, key: []const u8) ?u32 {
    const start = findField(body, key) orelse return null;
    var i = start;
    while (i < body.len and (body[i] >= '0' and body[i] <= '9')) : (i += 1) {}
    if (i == start) return null;
    return std.fmt.parseInt(u32, body[start..i], 10) catch null;
}

/// Read a `key: !N` metadata-ref field. Returns N.
fn fieldMetaRef(body: []const u8, key: []const u8) ?u32 {
    const start = findField(body, key) orelse return null;
    if (start >= body.len or body[start] != '!') return null;
    var i = start + 1;
    while (i < body.len and (body[i] >= '0' and body[i] <= '9')) : (i += 1) {}
    if (i == start + 1) return null;
    return std.fmt.parseInt(u32, body[start + 1 .. i], 10) catch null;
}

test "parseRecordLine: DIFile" {
    const line = "!9 = !DIFile(filename: \"ubsan_rt.zig\", directory: \"/usr/lib/zig\")";
    const r = parseRecordLine(line) orelse return error.TestFailed;
    try std.testing.expectEqual(@as(u32, 9), r.id);
    try std.testing.expectEqualStrings("ubsan_rt.zig", r.rec.file.filename);
    try std.testing.expectEqualStrings("/usr/lib/zig", r.rec.file.directory);
}

test "parseRecordLine: DISubprogram" {
    const line = "!4213 = distinct !DISubprogram(name: \"handler\", linkageName: \"ubsan_rt.overflowHandler.S.handler\", scope: !9, file: !9, line: 161, type: !4214, scopeLine: 165, flags: DIFlagStaticMember | DIFlagNoReturn, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !5)";
    const r = parseRecordLine(line) orelse return error.TestFailed;
    try std.testing.expectEqual(@as(u32, 4213), r.id);
    const sp = r.rec.subprogram;
    try std.testing.expectEqualStrings("handler", sp.name.?);
    try std.testing.expectEqualStrings("ubsan_rt.overflowHandler.S.handler", sp.linkage_name.?);
    try std.testing.expectEqual(@as(u32, 9), sp.file.?);
    try std.testing.expectEqual(@as(u32, 161), sp.line);
}

test "parseRecordLine: DILocation" {
    const line = "!4243 = !DILocation(line: 165, column: 33, scope: !4213)";
    const r = parseRecordLine(line) orelse return error.TestFailed;
    try std.testing.expectEqual(@as(u32, 4243), r.id);
    try std.testing.expectEqual(@as(u32, 165), r.rec.location.line);
    try std.testing.expectEqual(@as(u32, 33), r.rec.location.column);
    try std.testing.expectEqual(@as(u32, 4213), r.rec.location.scope.?);
}

test "parseRecordLine: DILexicalBlock" {
    const line = "!4239 = !DILexicalBlock(scope: !4213, file: !9, line: 168, column: 36)";
    const r = parseRecordLine(line) orelse return error.TestFailed;
    try std.testing.expectEqual(@as(u32, 4239), r.id);
    try std.testing.expectEqual(@as(u32, 4213), r.rec.lexical_block.scope.?);
    try std.testing.expectEqual(@as(u32, 9), r.rec.lexical_block.file.?);
}

test "Table.resolveSubprogram: lexical-block chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tbl = Table.init(arena.allocator());
    try tbl.put(100, .{ .subprogram = .{ .file = 1, .line = 10 } });
    try tbl.put(200, .{ .lexical_block = .{ .scope = 100, .file = 1 } });
    try tbl.put(300, .{ .lexical_block = .{ .scope = 200, .file = 1 } });
    try std.testing.expectEqual(@as(u32, 100), tbl.resolveSubprogram(300).?);
}
