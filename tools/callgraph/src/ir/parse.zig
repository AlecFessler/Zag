// LLVM IR parser for the kernel call-graph tool.
//
// Two-pass over the .ll text:
//
//   pass 1  collects function defs (`define ...`) and metadata records
//           (`!N = ...`). Function bodies' call instructions are buffered
//           as (caller_id, raw_target, dbg_id, indirect) so we don't yet
//           need the full metadata table to resolve them.
//
//   pass 2  resolves each pending edge: caller -> target FnId via a
//           name lookup, and dbg_id -> SourceLoc via the metadata table
//           (DILocation -> scope chain -> DISubprogram -> DIFile).
//
// All allocations come from the arena passed in by the caller. The IR file
// itself is read into the arena so string slices into it stay valid for the
// arena's lifetime.

const std = @import("std");

const md = @import("metadata.zig");
const types = @import("../types.zig");

const FnId = types.FnId;
const IrEdge = types.IrEdge;
const IrFunction = types.IrFunction;
const IrGraph = types.IrGraph;
const SourceLoc = types.SourceLoc;

/// Parse the IR file at `ir_path` into an IrGraph.
///
/// All returned slices are owned by `arena` (including the underlying string
/// data). The caller is responsible for arena.deinit().
pub fn parse(arena: *std.heap.ArenaAllocator, ir_path: []const u8) !IrGraph {
    const allocator = arena.allocator();

    // Read the whole file into the arena. ~16 MB for a typical kernel.ll —
    // fine for a dev tool. We slice strings out of this buffer.
    const file = try std.fs.cwd().openFile(ir_path, .{});
    defer file.close();
    const stat = try file.stat();
    const buf = try allocator.alloc(u8, stat.size);
    const n = try file.readAll(buf);
    if (n != buf.len) return error.ShortRead;
    const src = buf[0..n];

    var p = Parser{
        .allocator = allocator,
        .src = src,
        .functions = std.ArrayList(IrFunction){},
        .pending = std.ArrayList(PendingEdge){},
        .by_mangled = std.StringHashMap(FnId).init(allocator),
        .meta = md.Table.init(allocator),
    };

    try p.passOne();
    return try p.passTwo();
}

const PendingEdge = struct {
    from: FnId,
    target: ?[]const u8, // null = indirect
    dbg_id: ?u32,
    indirect: bool,
};

const Parser = struct {
    allocator: std.mem.Allocator,
    src: []const u8,
    functions: std.ArrayList(IrFunction),
    pending: std.ArrayList(PendingEdge),
    by_mangled: std.StringHashMap(FnId),
    meta: md.Table,
    /// Side table FnId -> !dbg id, populated in pass 1, consumed in pass 2
    /// to fill IrFunction.def_loc from the corresponding !DISubprogram.
    pending_defs: std.AutoHashMapUnmanaged(FnId, u32) = .{},

    /// Pass 1: scan line-by-line, build function table and metadata table,
    /// buffer pending edges with raw target names + dbg refs.
    fn passOne(self: *Parser) !void {
        var current_fn: ?FnId = null; // FnId of function whose body we're inside
        var brace_depth: i32 = 0; // tracks {/} once we're inside a body

        var it = std.mem.splitScalar(u8, self.src, '\n');
        while (it.next()) |raw_line| {
            // strip CR if present
            const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
                raw_line[0 .. raw_line.len - 1]
            else
                raw_line;

            if (line.len == 0) continue;

            // Module-level metadata definitions. They appear after the last
            // function body; current_fn will be null.
            if (line[0] == '!') {
                if (md.parseRecordLine(line)) |r| {
                    try self.meta.put(r.id, r.rec);
                }
                continue;
            }

            // Comments
            if (line[0] == ';') continue;

            if (current_fn == null) {
                // Outside any function body — only `define` lines matter.
                if (std.mem.startsWith(u8, line, "define ")) {
                    const fid = try self.recordFunctionDef(line);
                    current_fn = fid;
                    // If the line ends with `{` we're now inside the body.
                    brace_depth = if (lineEndsWithOpenBrace(line)) 1 else 0;
                }
                continue;
            }

            // Inside a function body. Track braces to find end-of-function.
            // Strings in IR are escaped with \xx, so '{' and '}' inside them
            // are emitted as `\7B` / `\7D` and won't affect us.
            for (line) |c| {
                if (c == '{') brace_depth += 1;
                if (c == '}') brace_depth -= 1;
            }
            if (brace_depth <= 0) {
                current_fn = null;
                brace_depth = 0;
                continue;
            }

            // Look for call/invoke instructions.
            try self.tryRecordCall(current_fn.?, line);
        }
    }

    /// If `line` is `define ... @NAME(...) ... !dbg !N {`, push an IrFunction
    /// with a *placeholder* def_loc (filled in pass 2 if !dbg is present).
    /// Returns the new FnId.
    fn recordFunctionDef(self: *Parser, line: []const u8) !FnId {
        const id: FnId = @intCast(self.functions.items.len);

        // Find the function symbol: the `@NAME(` immediately preceding the
        // argument list. Strategy: find the `(` whose `)` is followed by
        // attributes/`!dbg`/`{` (i.e. the outermost), then walk back to find
        // the `@`.
        const sym_paren = findCallSymbolParen(line, "define ".len) orelse {
            // Malformed define line — skip with a placeholder name.
            const empty: []const u8 = "";
            try self.functions.append(self.allocator, .{ .id = id, .mangled = empty });
            return id;
        };
        const at_pos = sym_paren.at;
        const name_end = sym_paren.paren;
        const ir_symbol = parseSymbolName(line, at_pos, name_end);

        // Extract trailing !dbg !N if present.
        const dbg_id = findTrailingDbgId(line);

        const mangled_default = ir_symbol;
        const fn_entry = IrFunction{ .id = id, .mangled = mangled_default };

        if (dbg_id) |did| {
            // Stash dbg_id in def_loc.line as a tag — we'll resolve in pass 2.
            // But IrFunction doesn't have such a field; use a side table.
            try self.pending_defs.put(self.allocator, id, did);
        }

        try self.functions.append(self.allocator, fn_entry);
        try self.by_mangled.put(mangled_default, id);
        return id;
    }

    /// If `line` is a call/invoke instruction, record a PendingEdge.
    fn tryRecordCall(self: *Parser, caller: FnId, line: []const u8) !void {
        // Skip leading whitespace.
        var i: usize = 0;
        while (i < line.len and (line[i] == ' ' or line[i] == '\t')) : (i += 1) {}
        if (i >= line.len) return;

        // Result-binding form: `%R = call ...`
        if (line[i] == '%') {
            // skip `%REG = `
            const eq = std.mem.indexOfScalarPos(u8, line, i, '=') orelse return;
            i = eq + 1;
            while (i < line.len and line[i] == ' ') : (i += 1) {}
        }

        // Optional tail/musttail/notail prefix
        i = consumeKeyword(line, i, "tail ") orelse
            consumeKeyword(line, i, "musttail ") orelse
            consumeKeyword(line, i, "notail ") orelse i;

        // Must be `call ` or `invoke `
        const after_kw =
            consumeKeyword(line, i, "call ") orelse
            consumeKeyword(line, i, "invoke ") orelse return;

        // Skip inline asm calls.
        // After "call " the type sig precedes the target. Inline asm has
        // " asm " (or "asm sideeffect"/"asm inteldialect" etc.) between the
        // type and the operand.
        if (std.mem.indexOfPos(u8, line, after_kw, " asm ") != null or
            std.mem.indexOfPos(u8, line, after_kw, "\tasm ") != null)
        {
            return;
        }

        // Find the call's argument paren — the `(` whose target precedes it.
        const sym_paren = findCallSymbolParen(line, after_kw) orelse return;
        const target_start = sym_paren.at; // index of '@' or '%'

        const indirect = line[target_start] == '%';
        var pe = PendingEdge{
            .from = caller,
            .target = null,
            .dbg_id = findTrailingDbgId(line),
            .indirect = indirect,
        };

        if (!indirect) {
            const name = parseSymbolName(line, target_start, sym_paren.paren);
            // Filter LLVM intrinsics — too noisy and never resolved as
            // user-visible edges anyway.
            if (std.mem.startsWith(u8, name, "llvm.")) return;
            pe.target = name;
        }

        try self.pending.append(self.allocator, pe);
    }

    /// Pass 2: resolve pending edges into IrEdges, fill in IrFunction.def_loc
    /// from DISubprogram/DIFile.
    fn passTwo(self: *Parser) !IrGraph {
        // Resolve mangled name from DISubprogram.linkageName when available.
        // We do this *after* the by_mangled table is built (in pass 1) using
        // the IR symbol; here we additionally register the linkageName alias
        // so calls that happen to use linkageName can still match. Zig emits
        // calls via the IR symbol so this rarely changes anything, but it
        // also gives us def_loc.
        var fi: usize = 0;
        while (fi < self.functions.items.len) : (fi += 1) {
            const f = &self.functions.items[fi];
            const dbg = self.pending_defs.get(f.id) orelse continue;
            const sp_rec = self.meta.get(dbg) orelse continue;
            const sp = switch (sp_rec) {
                .subprogram => |s| s,
                else => continue,
            };
            if (sp.linkage_name) |ln| {
                f.mangled = ln;
                // Make calls keyed on linkageName resolvable too.
                _ = self.by_mangled.fetchPut(ln, f.id) catch {};
            }
            f.def_loc = self.lookupFileLine(sp.file, sp.line);
        }

        // Edges.
        var edges = try self.allocator.alloc(IrEdge, self.pending.items.len);
        var ei: usize = 0;
        for (self.pending.items) |pe| {
            const site = self.resolveSite(pe.dbg_id) orelse SourceLoc{
                .file = "",
                .line = 0,
                .col = 0,
            };
            var to: ?FnId = null;
            if (pe.target) |t| {
                to = self.by_mangled.get(t);
            }
            edges[ei] = .{
                .from = pe.from,
                .to = to,
                .site = site,
                .indirect = pe.indirect,
            };
            ei += 1;
        }

        return .{
            .functions = try self.allocator.dupe(IrFunction, self.functions.items),
            .edges = edges,
        };
    }

    /// DILocation -> SourceLoc { file: <DIFile path>, line, col }.
    /// File is determined by walking the location's scope to a DISubprogram
    /// and using its `file` (DIFile) reference.
    fn resolveSite(self: *Parser, dbg_id: ?u32) ?SourceLoc {
        const did = dbg_id orelse return null;
        const rec = self.meta.get(did) orelse return null;
        const loc = switch (rec) {
            .location => |l| l,
            else => return null,
        };
        var file_path: []const u8 = "";
        if (loc.scope) |scope_id| {
            if (self.meta.resolveSubprogram(scope_id)) |sp_id| {
                if (self.meta.get(sp_id)) |sp_rec| switch (sp_rec) {
                    .subprogram => |sp| {
                        if (sp.file) |fid| {
                            file_path = self.fileRefToPath(fid);
                        }
                    },
                    else => {},
                };
            }
        }
        return .{ .file = file_path, .line = loc.line, .col = loc.column };
    }

    fn lookupFileLine(self: *Parser, file_id: ?u32, line: u32) ?SourceLoc {
        const fid = file_id orelse return null;
        return .{ .file = self.fileRefToPath(fid), .line = line, .col = 0 };
    }

    /// Format DIFile(directory + filename) as "<directory>/<filename>"
    /// (or just the filename if directory is empty). Allocates from the arena.
    fn fileRefToPath(self: *Parser, file_id: u32) []const u8 {
        const rec = self.meta.get(file_id) orelse return "";
        const fr = switch (rec) {
            .file => |f| f,
            else => return "",
        };
        if (fr.directory.len == 0) return fr.filename;
        if (fr.filename.len == 0) return fr.directory;
        // join with "/"
        const out = self.allocator.alloc(u8, fr.directory.len + 1 + fr.filename.len) catch return fr.filename;
        @memcpy(out[0..fr.directory.len], fr.directory);
        out[fr.directory.len] = '/';
        @memcpy(out[fr.directory.len + 1 ..], fr.filename);
        return out;
    }
};

// ---------- line-level helpers ----------

fn lineEndsWithOpenBrace(line: []const u8) bool {
    var i = line.len;
    while (i > 0) : (i -= 1) {
        const c = line[i - 1];
        if (c == ' ' or c == '\t') continue;
        return c == '{';
    }
    return false;
}

fn consumeKeyword(line: []const u8, i: usize, kw: []const u8) ?usize {
    if (i + kw.len > line.len) return null;
    if (!std.mem.eql(u8, line[i .. i + kw.len], kw)) return null;
    return i + kw.len;
}

/// Locate the function-symbol/argument-paren pair on a line.
///
/// Walks from `start` and finds the *outermost* '(' whose matching ')' is at
/// top-level — that ')' is followed by attributes / metadata / `{` / EOL.
/// Returns:
///   .at      = index of '@' or '%' identifying the target
///   .paren   = index of the '(' that opens the arg list
///
/// Skips '@' inside quoted strings (`@"foo bar"`) and inside parens that
/// belong to type signatures (e.g., `{ ptr, i64 }` is fine because `{` ≠ `(`,
/// but `i32 (i32)*` could appear in a function pointer type).
const SymParen = struct { at: usize, paren: usize };
fn findCallSymbolParen(line: []const u8, start: usize) ?SymParen {
    // Walk to find a top-level '(' such that immediately before it is either
    // an identifier (after '@' or '%' possibly quoted) and after walking back
    // we hit '@' or '%'.
    var depth: u32 = 0;
    var in_str = false;
    var i: usize = start;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (in_str) {
            if (c == '\\' and i + 1 < line.len) {
                i += 1;
                continue;
            }
            if (c == '"') in_str = false;
            continue;
        }
        switch (c) {
            '"' => in_str = true,
            '(' => {
                if (depth == 0) {
                    // candidate — check that the chars right before are an identifier
                    // tail and walk back to '@' or '%'.
                    if (walkBackToSigil(line, i)) |at_pos| {
                        return .{ .at = at_pos, .paren = i };
                    }
                }
                depth += 1;
            },
            ')' => if (depth > 0) {
                depth -= 1;
            },
            else => {},
        }
    }
    return null;
}

/// From an index pointing at '(', walk left over an identifier (optionally
/// quoted) to find the leading '@' or '%'. Returns the sigil index, or null.
fn walkBackToSigil(line: []const u8, paren: usize) ?usize {
    if (paren == 0) return null;
    var i: usize = paren;

    // Quoted form: `@"..."(` — i-1 is '"'
    if (i > 0 and line[i - 1] == '"') {
        // walk back to the matching opening '"'
        i -= 1;
        while (i > 0) {
            i -= 1;
            if (line[i] == '"') {
                // this is the opening quote; sigil should be at i-1
                if (i == 0) return null;
                const s = line[i - 1];
                if (s == '@' or s == '%') return i - 1;
                return null;
            }
            if (line[i] == '\\') {
                // escaped char — back over its 2 hex digits if present
                // \xx — the '\' is at i; we already moved past one char, so
                // just continue; this is approximate but fine for our purpose
            }
        }
        return null;
    }

    // Bare identifier form: `@<ident>(` or `%<ident>(`
    while (i > 0) {
        i -= 1;
        const c = line[i];
        if (c == '@' or c == '%') return i;
        if (isIdentChar(c)) continue;
        return null;
    }
    return null;
}

fn isIdentChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or
        (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or
        c == '_' or c == '.' or c == '$' or c == '-';
}

/// Slice the symbol name out of `line`, given the sigil (@ or %) at `at_pos`
/// and the opening '(' at `paren`. For quoted form `@"..."`, strips both the
/// sigil and surrounding quotes.
fn parseSymbolName(line: []const u8, at_pos: usize, paren: usize) []const u8 {
    if (at_pos + 1 >= line.len) return "";
    if (line[at_pos + 1] == '"' and paren > 0 and line[paren - 1] == '"') {
        return line[at_pos + 2 .. paren - 1];
    }
    return line[at_pos + 1 .. paren];
}

/// Find the trailing `, !dbg !N` on a line, return N. Returns null if absent.
fn findTrailingDbgId(line: []const u8) ?u32 {
    // Search for the last "!dbg !" occurrence (call lines have only one).
    var last_idx: ?usize = null;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, line, i, "!dbg !")) |idx| {
        last_idx = idx;
        i = idx + 1;
    }
    const idx = last_idx orelse return null;
    var j = idx + "!dbg !".len;
    const num_start = j;
    while (j < line.len and (line[j] >= '0' and line[j] <= '9')) : (j += 1) {}
    if (j == num_start) return null;
    return std.fmt.parseInt(u32, line[num_start..j], 10) catch null;
}

// ---------- tests ----------

test "findCallSymbolParen: bare name" {
    const line = "  call fastcc void @ubsan_rt.foo(ptr %0, i64 %1), !dbg !42";
    const sp = findCallSymbolParen(line, "  call fastcc void ".len) orelse return error.TestFailed;
    const name = parseSymbolName(line, sp.at, sp.paren);
    try std.testing.expectEqualStrings("ubsan_rt.foo", name);
}

test "findCallSymbolParen: quoted name" {
    const line = "  call fastcc void @\"debug.FullPanic((function 'panic')).outOfBounds\"(ptr %0, i64 1, i64 2), !dbg !99";
    const sp = findCallSymbolParen(line, "  call fastcc void ".len) orelse return error.TestFailed;
    const name = parseSymbolName(line, sp.at, sp.paren);
    try std.testing.expectEqualStrings("debug.FullPanic((function 'panic')).outOfBounds", name);
}

test "findCallSymbolParen: indirect via %reg" {
    const line = "  call fastcc void %42(ptr %0), !dbg !7";
    const sp = findCallSymbolParen(line, "  call fastcc void ".len) orelse return error.TestFailed;
    try std.testing.expectEqual(@as(u8, '%'), line[sp.at]);
}

test "findCallSymbolParen: define line with struct return" {
    const line = "define internal fastcc { ptr, i64 } @ubsan_rt.TypeDescriptor.getName(ptr nonnull %0, ptr %1) unnamed_addr #1 !dbg !4265 {";
    const sp = findCallSymbolParen(line, "define ".len) orelse return error.TestFailed;
    const name = parseSymbolName(line, sp.at, sp.paren);
    try std.testing.expectEqualStrings("ubsan_rt.TypeDescriptor.getName", name);
}

test "findTrailingDbgId" {
    try std.testing.expectEqual(@as(u32, 4243), findTrailingDbgId("  call void @x(), !dbg !4243").?);
    try std.testing.expectEqual(@as(?u32, null), findTrailingDbgId("  call void @x()"));
}

test "lineEndsWithOpenBrace" {
    try std.testing.expect(lineEndsWithOpenBrace("define ... !dbg !1 {"));
    try std.testing.expect(lineEndsWithOpenBrace("define ... !dbg !1 {  "));
    try std.testing.expect(!lineEndsWithOpenBrace("declare void @x()"));
}
