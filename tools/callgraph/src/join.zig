// IR ↔ AST join + Graph builder.
//
// Combines an IrGraph (mangled fn names + call edges from LLVM IR) with the
// AstFunction list emitted by ast/walker.zig, producing a Graph the server
// can render. The primary join key is `(absolute_file, line)` — IR's def_loc
// and AST's `line_start` should agree on the line of the `fn` keyword.
//
// Some IR DISubprograms point at stale lines (kernel.ll generated against an
// older checkout) or carry per-instantiation copies of the same source-level
// fn (every `SecureSlab(T,256).init` shares one DISubprogram line in the IR
// regardless of where the source-level method actually sits). When the
// (file, line) lookup misses we fall back to a name-based lookup against the
// AST's `qualified_name`, after stripping `(...)` generic args and
// `__anon_NNNN` / `__enum_NNNN` / `__struct_NNNN` instantiation suffixes off
// the IR's mangled name.
//
// For each IR function with a successful AST match, `display_name` is set to
// the AST's qualified name (e.g. `memory.pmm.alloc`). On miss we fall back
// to the IR mangled name, which Zig already emits in a near-readable form.
//
// Each EnrichedEdge gets `target_name` filled in from the resolved target
// function's display name when possible.
//
// Entry-point marking: callers pass a `[]const entry.Discovered` produced
// by `entry.discover` in main.zig. We index it by qualified name and stamp
// `is_entry` / `entry_kind` on every matching `Function`, then emit one
// `EntryPoint` per match (with the discovered label).

const std = @import("std");

const ast = @import("ast/index.zig");
const branches = @import("ast/branches.zig");
const entry_mod = @import("entry.zig");
const types = @import("types.zig");

const AstFunction = ast.AstFunction;
const FileAst = ast.FileAst;
const Discovered = entry_mod.Discovered;

pub const JoinStats = struct {
    ir_total: usize,
    matched: usize,
};

pub fn buildGraph(
    arena: std.mem.Allocator,
    ir_graph: types.IrGraph,
    ast_fns: []const AstFunction,
) !types.Graph {
    var stats: JoinStats = .{ .ir_total = 0, .matched = 0 };
    return try buildGraphWithStats(arena, ir_graph, ast_fns, &.{}, &.{}, .x86_64, &stats);
}

pub fn buildGraphWithStats(
    arena: std.mem.Allocator,
    ir_graph: types.IrGraph,
    ast_fns: []const AstFunction,
    file_asts: []const FileAst,
    discovered: []const Discovered,
    target_arch: types.TargetArch,
    stats_out: *JoinStats,
) !types.Graph {
    // Build a (file_abs, line) → AstFunction lookup. Use a string-keyed map
    // composing "<abs_path>:<line>" — saves us a custom hasher and avoids
    // the per-key allocation of a struct hash with two slices.
    var ast_index = std.StringHashMap(*const AstFunction).init(arena);

    // Cache realpath resolutions per file path so we don't re-syscall the
    // same paths once per IR function. The IR side has a single canonical
    // path per file, but it may differ in normalization from what the AST
    // walker emits. We resolve both sides through the same cache.
    var realpath_cache = std.StringHashMap([]const u8).init(arena);

    // Secondary index keyed by AST `qualified_name`. Used as a fallback when
    // the primary (file, line) join misses — typically because the IR's
    // DISubprogram line is stale, or the Zig compiler emitted a misleading
    // line for a generic-instantiated method (e.g. every
    // `SecureSlab(T,256).init` shares the same DISubprogram line regardless
    // of where the source-level `pub fn init` actually sits). Stripping
    // `(...)` generic args from the IR `mangled`/`linkageName` collapses
    // every instantiation onto the single AST entry the walker emits for
    // the underlying source fn.
    var ast_by_qname = std.StringHashMap(*const AstFunction).init(arena);
    for (ast_fns) |*af| {
        const resolved = try resolvePath(arena, &realpath_cache, af.file);
        const key = try std.fmt.allocPrint(arena, "{s}:{d}", .{ resolved, af.line_start });
        // Last-write-wins on collision; collisions would be e.g. two fns
        // declared on the same line, which Zig disallows. Practically this
        // never happens.
        try ast_index.put(key, af);
        // First-write-wins for the qname index — if the walker emits two
        // entries with the same qualified name (rare; happens with
        // re-exported aliases) we keep the first one we saw, which is the
        // earlier-walked top-level definition.
        _ = try ast_by_qname.getOrPutValue(af.qualified_name, af);
    }

    // Bucket IR edges by `from`.
    var edges_by_fn = std.AutoHashMap(types.FnId, std.ArrayList(types.EnrichedEdge)).init(arena);
    for (ir_graph.edges) |edge| {
        const kind: types.EdgeKind = if (edge.indirect or edge.to == null)
            .indirect
        else
            .direct;
        const enriched = types.EnrichedEdge{
            .to = edge.to,
            .target_name = null,
            .kind = kind,
            .site = edge.site,
        };
        const gop = try edges_by_fn.getOrPut(edge.from);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.append(arena, enriched);
    }

    // First pass: build Function records with resolved display names.
    var functions = try arena.alloc(types.Function, ir_graph.functions.len);
    var matched: usize = 0;
    for (ir_graph.functions, 0..) |ir_fn, i| {
        var display_name: []const u8 = ir_fn.mangled;
        var def_loc: types.SourceLoc = ir_fn.def_loc orelse .{ .file = "<unknown>", .line = 0, .col = 0 };

        if (ir_fn.def_loc) |loc| {
            const resolved = resolvePath(arena, &realpath_cache, loc.file) catch loc.file;
            const key = try std.fmt.allocPrint(arena, "{s}:{d}", .{ resolved, loc.line });
            if (ast_index.get(key)) |af| {
                display_name = af.qualified_name;
                matched += 1;
                // Substitute resolved file in def_loc so the frontend's
                // /api/source endpoint sees a path it can open.
                def_loc = .{ .file = resolved, .line = loc.line, .col = loc.col };
            } else if (lookupByQName(arena, &ast_by_qname, ir_fn.mangled)) |af| {
                // Fallback: name-based lookup. Snap the IR-reported def_loc
                // onto the AST's truth so downstream consumers (intra
                // builder, /api/source) see a coherent file:line.
                display_name = af.qualified_name;
                matched += 1;
                def_loc = .{ .file = af.file, .line = af.line_start, .col = 0 };
            }
        }

        const callees: []types.EnrichedEdge = if (edges_by_fn.get(ir_fn.id)) |list|
            try arena.dupe(types.EnrichedEdge, list.items)
        else
            &.{};
        functions[i] = .{
            .id = ir_fn.id,
            .name = display_name,
            .mangled = ir_fn.mangled,
            .def_loc = def_loc,
            .is_entry = false,
            .entry_kind = null,
            .callees = callees,
        };
    }

    // Second pass: fill in EnrichedEdge.target_name from each resolved target's
    // display name. Done after the first pass so callees see the joined names.
    for (functions) |*f| {
        for (f.callees) |*e| {
            const to = e.to orelse continue;
            if (to >= functions.len) continue;
            e.target_name = functions[to].name;
        }
    }

    // Third pass: build intra-procedural branch trees for every function
    // that has a corresponding AST entry. We need:
    //   1) a file → FileAst lookup so we can get the parsed std.zig.Ast.
    //   2) a (def_loc.file, def_loc.line) → AstFunction lookup so we know
    //      the AST fn_decl node index.
    //   3) per function, a CallSiteMap keyed by `<file>:<line>` containing
    //      every Callee whose `from` matches this function's IR id.
    if (file_asts.len > 0) {
        try attachIntra(arena, functions, ast_fns, file_asts, &realpath_cache, target_arch);
    }

    // Stamp `is_entry` / `entry_kind` on every function whose qualified name
    // appears in the discovered set, and emit a corresponding EntryPoint.
    var entry_points = std.ArrayList(types.EntryPoint){};
    try markEntryPoints(arena, functions, discovered, &entry_points);

    stats_out.* = .{ .ir_total = ir_graph.functions.len, .matched = matched };

    return .{
        .functions = functions,
        .entry_points = try entry_points.toOwnedSlice(arena),
    };
}

/// Strip every parenthesized run from `mangled` and look the result up in the
/// AST qualified-name index. Generic instantiations look like
/// `pkg.path.SecureSlab(T,256).init` in the IR; the AST walker emits
/// `pkg.path.SecureSlab.init`. We also strip trailing `__anon_NNNN` /
/// `__enum_NNNN` / `__struct_NNNN` suffixes the Zig backend appends to
/// per-instantiation copies of inline / anonymous fns. We try a few
/// progressively-coarsened forms before giving up.
fn lookupByQName(
    arena: std.mem.Allocator,
    index: *std.StringHashMap(*const AstFunction),
    mangled: []const u8,
) ?*const AstFunction {
    // Cheap pre-check: nothing to strip means the mangled name was already a
    // plain qualified name; the (file, line) lookup would only have missed
    // because of stale debug-info lines, but the qname index can still hit.
    if (index.get(mangled)) |hit| return hit;

    // 1. Drop `(...)` generic-arg runs.
    const no_parens = stripBalancedParens(arena, mangled) catch return null;
    if (index.get(no_parens)) |hit| return hit;

    // 2. Drop trailing `__<tag>_<digits>` segments (one per dot-segment).
    const no_anon = stripAnonSuffixes(arena, no_parens) catch return null;
    if (index.get(no_anon)) |hit| return hit;

    return null;
}

/// Remove every `(...)` substring (including nested parens). Returns a copy
/// allocated in `arena`.
fn stripBalancedParens(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out = std.ArrayList(u8){};
    var depth: u32 = 0;
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '(') {
            depth += 1;
        } else if (c == ')') {
            if (depth > 0) depth -= 1;
        } else if (depth == 0) {
            try out.append(arena, c);
        }
        i += 1;
    }
    return out.toOwnedSlice(arena);
}

/// For each dot-separated segment, drop a trailing `__<tag>_<digits>` suffix.
/// E.g. `arch.dispatch.boot.print__anon_6690` → `arch.dispatch.boot.print`,
/// `ubsan_rt.TypeMismatchData__enum_1811.getName` →
/// `ubsan_rt.TypeMismatchData.getName`.
fn stripAnonSuffixes(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out = std.ArrayList(u8){};
    var seg_start: usize = 0;
    var i: usize = 0;
    while (i <= s.len) {
        const at_end = i == s.len;
        if (at_end or s[i] == '.') {
            const seg = s[seg_start..i];
            const trimmed = stripOneAnonSuffix(seg);
            try out.appendSlice(arena, trimmed);
            if (!at_end) try out.append(arena, '.');
            seg_start = i + 1;
        }
        i += 1;
    }
    return out.toOwnedSlice(arena);
}

fn stripOneAnonSuffix(seg: []const u8) []const u8 {
    // Look for `__` from the right.
    var k: usize = seg.len;
    while (k >= 2) : (k -= 1) {
        if (seg[k - 2] == '_' and seg[k - 1] == '_') {
            // Everything after `__` is supposed to be `<tag>_<digits>` where
            // <tag> is alphabetic. Verify cheaply.
            const tail = seg[k..];
            if (tail.len < 3) return seg;
            const us = std.mem.indexOfScalar(u8, tail, '_') orelse return seg;
            const tag = tail[0..us];
            const digits = tail[us + 1 ..];
            if (tag.len == 0 or digits.len == 0) return seg;
            for (tag) |c| if (!std.ascii.isAlphabetic(c)) return seg;
            for (digits) |c| if (!std.ascii.isDigit(c)) return seg;
            return seg[0 .. k - 2];
        }
    }
    return seg;
}

fn resolvePath(
    arena: std.mem.Allocator,
    cache: *std.StringHashMap([]const u8),
    path: []const u8,
) ![]const u8 {
    if (cache.get(path)) |hit| return hit;
    const resolved = std.fs.realpathAlloc(arena, path) catch try arena.dupe(u8, path);
    // Use the original path as the cache key (cheaper than the resolved one
    // and the IR/AST sides each present consistent inputs).
    try cache.put(try arena.dupe(u8, path), resolved);
    return resolved;
}

/// Stamp `is_entry` and `entry_kind` on every function whose `name` (i.e. the
/// AST qualified name we resolved during the join) matches a discovered entry,
/// and emit one EntryPoint per match. Functions that the join failed to map
/// to an AST entry keep their fallback IR-mangled name in `f.name`, which
/// won't match anything in the discovered set — that's the correct behaviour.
fn markEntryPoints(
    arena: std.mem.Allocator,
    functions: []types.Function,
    discovered: []const Discovered,
    out: *std.ArrayList(types.EntryPoint),
) !void {
    if (discovered.len == 0) return;
    var by_name = std.StringHashMap(*const Discovered).init(arena);
    for (discovered) |*d| try by_name.put(d.name, d);
    for (functions) |*f| {
        const d = by_name.get(f.name) orelse continue;
        f.is_entry = true;
        f.entry_kind = d.kind;
        try out.append(arena, .{
            .fn_id = f.id,
            .kind = d.kind,
            .label = d.label orelse f.name,
        });
    }
}

// ----------------------------------------------------------------- intra

fn attachIntra(
    arena: std.mem.Allocator,
    functions: []types.Function,
    ast_fns: []const AstFunction,
    file_asts: []const FileAst,
    realpath_cache: *std.StringHashMap([]const u8),
    target_arch: types.TargetArch,
) !void {
    // file (resolved abs path) -> FileAst
    var file_to_ast = std.StringHashMap(*const FileAst).init(arena);
    for (file_asts) |*fa| {
        const resolved = try resolvePath(arena, realpath_cache, fa.file);
        try file_to_ast.put(resolved, fa);
    }

    // (resolved file:line) -> AstFunction (with fn_node)
    var file_line_to_ast = std.StringHashMap(*const AstFunction).init(arena);
    for (ast_fns) |*af| {
        const resolved = try resolvePath(arena, realpath_cache, af.file);
        const key = try std.fmt.allocPrint(arena, "{s}:{d}", .{ resolved, af.line_start });
        try file_line_to_ast.put(key, af);
    }

    // Build the global qualified-name → fn-id index. branches.zig uses this
    // to resolve `Foo.bar()` calls when the IR doesn't have an edge at the
    // site (e.g. comptime arch-pruned arms). Functions that didn't join to
    // an AST entry keep their fallback IR-mangled name in `f.name`; including
    // those entries here is harmless — the resolver only hits keys that match
    // an `<imported_module>.<rest>` candidate built from a known import.
    var qname_index = branches.QNameIndex.init(arena);
    for (functions) |*f| {
        // First-write-wins to mirror the secondary index in buildGraphWithStats.
        _ = try qname_index.getOrPutValue(f.name, f.id);
    }

    // Companion set of every AST-known qualified name. The IR drops inline
    // and comptime functions; they still exist in the AST walker output, and
    // resolving a call to one of them is more useful than `? indirect`.
    var known_names = branches.KnownNames.init(arena);
    for (ast_fns) |af| {
        try known_names.put(af.qualified_name, {});
    }

    // Build per-function call-site maps. For each EnrichedEdge in each
    // function, key by `<resolved_site_file>:<line>` and append a Callee.
    // We build a transient list of edges per function id and only convert
    // for joined functions to avoid wasted work.
    for (functions) |*f| {
        // Skip if no def_loc file or it didn't match an AST fn.
        const resolved_def = resolvePath(arena, realpath_cache, f.def_loc.file) catch f.def_loc.file;
        const def_key = try std.fmt.allocPrint(arena, "{s}:{d}", .{ resolved_def, f.def_loc.line });
        const af = file_line_to_ast.get(def_key) orelse continue;
        if (af.fn_node == 0) continue;

        // Find this file's parsed AST.
        const fa = file_to_ast.get(resolved_def) orelse continue;

        // Build the call-site map for this function.
        var sites = branches.CallSiteMap.init(arena);
        // Group callees by `<file>:<line>` so we can stash a slice per key.
        var grouped = std.StringHashMap(std.ArrayList(types.Callee)).init(arena);
        for (f.callees) |e| {
            const site_file = resolvePath(arena, realpath_cache, e.site.file) catch e.site.file;
            const k = try branches.callSiteKey(arena, site_file, e.site.line);
            const callee = types.Callee{
                .to = e.to,
                .name = e.target_name orelse "?",
                .kind = e.kind,
                .site = .{ .file = site_file, .line = e.site.line, .col = e.site.col },
            };
            const gop = try grouped.getOrPut(k);
            if (!gop.found_existing) gop.value_ptr.* = .{};
            try gop.value_ptr.append(arena, callee);
        }
        var it = grouped.iterator();
        while (it.next()) |entry| {
            try sites.put(entry.key_ptr.*, try arena.dupe(types.Callee, entry.value_ptr.items));
        }

        f.intra = branches.buildIntra(
            arena,
            resolved_def,
            af.fn_node,
            fa.tree,
            sites,
            target_arch,
            &fa.imports,
            &qname_index,
            &known_names,
            af.receiver_name,
            af.receiver_type,
        ) catch &.{};
    }
}
