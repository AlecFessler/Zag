//! Function → Definition dependency edges.
//!
//! Walks every fn's signature + body in token order, harvests identifier
//! references and dotted chains, and resolves each against:
//!   1. the file's import table (a binding name like `pmm` → module path)
//!   2. the file's own module path (for same-file refs like `Foo`)
//!   3. the global def-qname index built from `Graph.definitions`
//!   4. the re-export alias table (rewrites `<mod>.X` to its underlying)
//!
//! Successful resolutions become entries in `Function.def_deps`. Unresolved
//! refs are dropped silently — fail-open. The diff/review feature uses these
//! edges so a struct edit flags every fn that depends on it, not just fns
//! whose own line range was touched.
//!
//! Phase 2 of the diff feature; phase 1 produced `Definition` records.

const std = @import("std");

const ast_mod = @import("ast/index.zig");
const types = @import("types.zig");

const FileAst = ast_mod.FileAst;
const ImportTable = ast_mod.walker.ImportTable;

const DepSet = std.AutoArrayHashMap(types.DefId, void);

/// Compute and install def_deps for every function in `graph`. Idempotent —
/// each call overwrites the previous def_deps slice. `file_asts` is the
/// walker's per-file (tree, source, imports) bundle; `aliases` is its
/// re-export alias table.
pub fn compute(
    arena: std.mem.Allocator,
    graph: *types.Graph,
    file_asts: []const FileAst,
    aliases: []const types.ReexportAlias,
) !void {
    if (graph.definitions.len == 0 or graph.functions.len == 0) return;

    var qname_to_def = std.StringHashMap(types.DefId).init(arena);
    defer qname_to_def.deinit();
    for (graph.definitions) |d| {
        _ = try qname_to_def.getOrPutValue(d.qualified_name, d.id);
    }

    var alias_map = std.StringHashMap([]const u8).init(arena);
    defer alias_map.deinit();
    for (aliases) |a| {
        _ = try alias_map.getOrPutValue(a.key, a.target);
    }

    // Per-file lookup: (file_path) → (FileAst, module_path). The module
    // path is computed once per file and reused across every fn in that
    // file. Computing it per-fn would be the obvious shape but it's
    // measurable overhead at ~25k fns.
    const FileBundle = struct {
        fa: *const FileAst,
        module_path: []const u8,
    };
    var file_index = std.StringHashMap(FileBundle).init(arena);
    defer file_index.deinit();
    for (file_asts) |*fa| {
        const mod = ast_mod.walker.filePathToModulePath(arena, fa.file) catch continue;
        try file_index.put(fa.file, .{ .fa = fa, .module_path = mod });
    }

    for (graph.functions) |*fn_rec| {
        const file = fn_rec.def_loc.file;
        const bundle = file_index.get(file) orelse continue;
        const tree = bundle.fa.tree;

        const fn_node = findFnNode(tree, fn_rec) orelse continue;

        var deps = DepSet.init(arena);
        defer deps.deinit();

        try collectDepsForFn(
            arena,
            tree,
            bundle.fa.imports,
            bundle.module_path,
            fn_node,
            &deps,
            &qname_to_def,
            &alias_map,
        );

        if (deps.count() == 0) continue;

        const out = try arena.alloc(types.DefId, deps.count());
        var i: usize = 0;
        var it = deps.iterator();
        while (it.next()) |entry| {
            out[i] = entry.key_ptr.*;
            i += 1;
        }
        fn_rec.def_deps = out;
    }
}

/// Locate the AST node index for `fn_rec` in `tree` by scanning fn_decls
/// for a start-line match. The fn name on `Function` is the joined
/// qualified name (`module.Container.simple_name`), so we compare against
/// the last segment to find the matching fn_proto. Line is the primary
/// disambiguator since two fns can never start on the same line.
fn findFnNode(tree: *std.zig.Ast, fn_rec: *const types.Function) ?std.zig.Ast.Node.Index {
    const target_line = fn_rec.def_loc.line;
    if (target_line == 0) return null;

    const simple_name = lastSegment(fn_rec.name);

    const node_count = tree.nodes.len;
    var i: u32 = 0;
    while (i < node_count) : (i += 1) {
        const idx: std.zig.Ast.Node.Index = @enumFromInt(i);
        const tag = tree.nodeTag(idx);
        const matches = switch (tag) {
            .fn_decl, .fn_proto, .fn_proto_simple, .fn_proto_multi, .fn_proto_one => true,
            else => false,
        };
        if (!matches) continue;

        var proto_buf: [1]std.zig.Ast.Node.Index = undefined;
        const fn_proto = tree.fullFnProto(&proto_buf, idx) orelse continue;

        const start_loc = tree.tokenLocation(0, fn_proto.ast.fn_token);
        const start_line: u32 = @intCast(start_loc.line + 1);
        if (start_line != target_line) continue;

        // Tie-break by simple name when multiple fns somehow share a
        // start line (shouldn't happen in real code, but Zig allows it
        // syntactically with a non-newline-separated decl).
        const name_tok = fn_proto.name_token orelse continue;
        const name = tree.tokenSlice(name_tok);
        if (simple_name.len > 0 and !std.mem.eql(u8, name, simple_name)) continue;

        return idx;
    }
    return null;
}

fn lastSegment(s: []const u8) []const u8 {
    const idx = std.mem.lastIndexOfScalar(u8, s, '.') orelse return s;
    return s[idx + 1 ..];
}

fn collectDepsForFn(
    arena: std.mem.Allocator,
    tree: *std.zig.Ast,
    imports: ImportTable,
    file_module: []const u8,
    fn_node: std.zig.Ast.Node.Index,
    deps: *DepSet,
    qname_to_def: *const std.StringHashMap(types.DefId),
    alias_map: *const std.StringHashMap([]const u8),
) !void {
    const first_tok = tree.firstToken(fn_node);
    const last_tok = tree.lastToken(fn_node);
    if (first_tok > last_tok) return;

    var i: u32 = first_tok;
    while (i <= last_tok) : (i += 1) {
        const tag = tree.tokenTag(i);
        if (tag != .identifier) continue;

        // Skip middle/tail of a dotted chain — those are picked up when we
        // process the head.
        if (i > 0 and tree.tokenTag(i - 1) == .period) continue;

        // Skip name-binding contexts. Heuristics:
        //   `fn name`, `var name`, `const name` — decl name (the binding,
        //     not a reference). The decl's BODY is walked separately.
        //   `name :` — param name or var-decl name (binding + type-anno)
        if (i > 0) {
            const prev_tag = tree.tokenTag(i - 1);
            if (prev_tag == .keyword_fn or prev_tag == .keyword_var or prev_tag == .keyword_const) {
                continue;
            }
        }
        if (i < last_tok and tree.tokenTag(i + 1) == .colon) continue;

        // Gather chain forward: <ident> (`.` <ident>)*
        var chain_end: u32 = i;
        var probe: u32 = i;
        while (probe < last_tok) {
            const next = probe + 1;
            if (next > last_tok or tree.tokenTag(next) != .period) break;
            const ident = next + 1;
            if (ident > last_tok or tree.tokenTag(ident) != .identifier) break;
            chain_end = ident;
            probe = ident;
        }

        try resolveChain(arena, tree, imports, file_module, i, chain_end, deps, qname_to_def, alias_map);
        i = chain_end;
    }
}

fn resolveChain(
    arena: std.mem.Allocator,
    tree: *std.zig.Ast,
    imports: ImportTable,
    file_module: []const u8,
    head_tok: u32,
    last_tok: u32,
    deps: *DepSet,
    qname_to_def: *const std.StringHashMap(types.DefId),
    alias_map: *const std.StringHashMap([]const u8),
) !void {
    // Collect segments. The chain alternates ident . ident . ident, so
    // every other token in [head_tok, last_tok] is an identifier.
    var segments = std.ArrayList([]const u8){};
    defer segments.deinit(arena);
    var t: u32 = head_tok;
    while (t <= last_tok) : (t += 2) {
        if (tree.tokenTag(t) != .identifier) break;
        try segments.append(arena, tree.tokenSlice(t));
        if (t == last_tok) break;
    }
    if (segments.items.len == 0) return;

    // Resolution priority:
    //   1. import-resolved head + remaining segments. Drop tail segments
    //      from the right until we either match or run out.
    //   2. file-module + raw segments (same-file ref).
    if (imports.get(segments.items[0])) |head_mod| {
        var keep: usize = segments.items.len;
        while (keep >= 1) : (keep -= 1) {
            const candidate = try joinQname(arena, head_mod, segments.items[1..keep]);
            if (try tryResolve(candidate, deps, qname_to_def, alias_map)) return;
            if (keep == 1) break;
        }
    }

    if (file_module.len > 0) {
        var keep: usize = segments.items.len;
        while (keep >= 1) : (keep -= 1) {
            const candidate = try joinQname(arena, file_module, segments.items[0..keep]);
            if (try tryResolve(candidate, deps, qname_to_def, alias_map)) return;
            if (keep == 1) break;
        }
    }
}

fn tryResolve(
    qname: []const u8,
    deps: *DepSet,
    qname_to_def: *const std.StringHashMap(types.DefId),
    alias_map: *const std.StringHashMap([]const u8),
) !bool {
    if (qname_to_def.get(qname)) |id| {
        try deps.put(id, {});
        return true;
    }
    if (alias_map.get(qname)) |target| {
        if (qname_to_def.get(target)) |id| {
            try deps.put(id, {});
            return true;
        }
    }
    return false;
}

fn joinQname(
    arena: std.mem.Allocator,
    module_path: []const u8,
    segs: []const []const u8,
) ![]const u8 {
    if (segs.len == 0) return arena.dupe(u8, module_path);
    var total: usize = module_path.len;
    for (segs) |s| total += 1 + s.len;
    const buf = try arena.alloc(u8, total);
    @memcpy(buf[0..module_path.len], module_path);
    var w: usize = module_path.len;
    for (segs) |s| {
        buf[w] = '.';
        w += 1;
        @memcpy(buf[w .. w + s.len], s);
        w += s.len;
    }
    return buf;
}
