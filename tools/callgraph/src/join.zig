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
    /// Number of AST-only Function records emitted (synthetic ids
    /// `>= ir_total`). These represent functions LLVM inlined entirely so
    /// the IR carries no `define` for them. Their intra tree is built from
    /// the AST walk and lets Trace mode drill through inlined helpers.
    ast_only: usize = 0,
};

pub fn buildGraph(
    arena: std.mem.Allocator,
    ir_graph: types.IrGraph,
    ast_fns: []const AstFunction,
) !types.Graph {
    var stats: JoinStats = .{ .ir_total = 0, .matched = 0 };
    return try buildGraphWithStats(arena, ir_graph, ast_fns, &.{}, &.{}, &.{}, &.{}, .x86_64, &stats);
}

pub fn buildGraphWithStats(
    arena: std.mem.Allocator,
    ir_graph: types.IrGraph,
    ast_fns: []const AstFunction,
    file_asts: []const FileAst,
    struct_types: []const types.StructTypeInfo,
    aliases: []const types.ReexportAlias,
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

    // First pass: build Function records with resolved display names. We
    // also track which AstFunction pointers got matched to an IR fn so the
    // AST-only emission below can skip them.
    //
    // `matched_ast` is keyed by AstFunction pointer addr (cheap, unique per
    // walker entry) and contains every AST fn that successfully joined to
    // an IR record. Functions still in the AST after this pass are the
    // candidates for the AST-only emission.
    var matched_ast = std.AutoHashMap(*const AstFunction, void).init(arena);

    var ir_functions = try arena.alloc(types.Function, ir_graph.functions.len);
    var matched: usize = 0;
    for (ir_graph.functions, 0..) |ir_fn, i| {
        var display_name: []const u8 = ir_fn.mangled;
        var def_loc: types.SourceLoc = ir_fn.def_loc orelse .{ .file = "<unknown>", .line = 0, .col = 0 };
        var body_line_end: u32 = 0;

        if (ir_fn.def_loc) |loc| {
            const resolved = resolvePath(arena, &realpath_cache, loc.file) catch loc.file;
            const key = try std.fmt.allocPrint(arena, "{s}:{d}", .{ resolved, loc.line });
            if (ast_index.get(key)) |af| {
                display_name = af.qualified_name;
                matched += 1;
                try matched_ast.put(af, {});
                // Substitute resolved file in def_loc so the frontend's
                // /api/source endpoint sees a path it can open.
                def_loc = .{ .file = resolved, .line = loc.line, .col = loc.col };
                body_line_end = af.line_end;
            } else if (lookupByQName(arena, &ast_by_qname, ir_fn.mangled)) |af| {
                // Fallback: name-based lookup. Snap the IR-reported def_loc
                // onto the AST's truth so downstream consumers (intra
                // builder, /api/source) see a coherent file:line.
                display_name = af.qualified_name;
                matched += 1;
                try matched_ast.put(af, {});
                def_loc = .{ .file = af.file, .line = af.line_start, .col = 0 };
                body_line_end = af.line_end;
            }
        }

        const callees: []types.EnrichedEdge = if (edges_by_fn.get(ir_fn.id)) |list|
            try arena.dupe(types.EnrichedEdge, list.items)
        else
            &.{};
        ir_functions[i] = .{
            .id = ir_fn.id,
            .name = display_name,
            .mangled = ir_fn.mangled,
            .def_loc = def_loc,
            .body_line_end = body_line_end,
            .is_entry = false,
            .entry_kind = null,
            .callees = callees,
            .is_ast_only = false,
        };
    }

    // Second pass: synthesize Function records for every AstFunction that
    // didn't match an IR fn — typically `pub inline fn` helpers LLVM
    // inlined entirely, plus comptime fns that left no IR `define`.
    //
    // Synthetic ids start at `ir_graph.functions.len` (callers can identify
    // AST-only entries by id range or by the `is_ast_only` flag). The
    // mangled field equals `name` since there's no real linkage symbol.
    // No IR edges → empty `callees`; the intra tree carries the call info,
    // built later in `attachIntra` via the import / qname / receiver-method
    // resolvers.
    //
    // We skip AST fns under `/usr/lib/zig/` since the existing frontend
    // library filter would hide them anyway and the JSON cost is wasted.
    var ast_only_list = std.ArrayList(types.Function){};
    var next_id: types.FnId = @intCast(ir_graph.functions.len);
    for (ast_fns) |*af| {
        if (matched_ast.contains(af)) continue;
        if (std.mem.startsWith(u8, af.file, "/usr/lib/zig/")) continue;
        if (af.fn_node == 0) continue;

        try ast_only_list.append(arena, .{
            .id = next_id,
            .name = af.qualified_name,
            .mangled = af.qualified_name,
            .def_loc = .{ .file = af.file, .line = af.line_start, .col = 0 },
            .body_line_end = af.line_end,
            .is_entry = false,
            .entry_kind = null,
            .callees = &.{},
            .is_ast_only = true,
        });
        next_id += 1;
    }
    const ast_only_count = ast_only_list.items.len;

    // Concatenate IR-backed + AST-only into the final `functions` slice.
    // Order: IR-backed first (preserves their existing ids), then AST-only
    // (synthetic ids contiguous from `ir_graph.functions.len`).
    var functions = try arena.alloc(types.Function, ir_functions.len + ast_only_count);
    @memcpy(functions[0..ir_functions.len], ir_functions);
    @memcpy(functions[ir_functions.len..], ast_only_list.items);

    // Third pass: fill in EnrichedEdge.target_name from each resolved
    // target's display name. Done after both Function passes so callees
    // see the joined names. AST-only fns have no callees so this is a
    // no-op for their slots.
    for (functions) |*f| {
        for (f.callees) |*e| {
            const to = e.to orelse continue;
            if (to >= functions.len) continue;
            e.target_name = functions[to].name;
        }
    }

    // Fourth pass: build intra-procedural branch trees for every function
    // we have an AST entry for. attachIntra builds the unified qname index
    // (covering BOTH IR-backed and AST-only ids) before running
    // branches.buildIntra, so call sites whose targets are AST-only
    // resolve to a real synthetic id rather than a `to=null` named leaf.
    if (file_asts.len > 0) {
        try attachIntra(arena, functions, ast_fns, file_asts, struct_types, aliases, &realpath_cache, target_arch);
    }

    // Stamp `is_entry` / `entry_kind` on every function whose qualified name
    // appears in the discovered set, and emit a corresponding EntryPoint.
    var entry_points = std.ArrayList(types.EntryPoint){};
    try markEntryPoints(arena, functions, discovered, &entry_points);

    stats_out.* = .{
        .ir_total = ir_graph.functions.len,
        .matched = matched,
        .ast_only = ast_only_count,
    };

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
    struct_types: []const types.StructTypeInfo,
    aliases: []const types.ReexportAlias,
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

    // Struct-qname → StructTypeInfo index. The receiver-chain resolver in
    // branches.zig consults this when walking each `.field` segment of
    // `self.x.y.method()` chains. First-write-wins on collision (rare —
    // would only happen if the walker emitted two structs at the same
    // qname, e.g. two `const Foo = struct {...}` in the same file).
    var struct_type_index = branches.StructTypeIndex.init(arena);
    for (struct_types) |*sti| {
        _ = try struct_type_index.getOrPutValue(sti.qname, sti);
    }

    // Re-export alias index. `lookupCandidate` consults this on a miss to
    // rewrite a candidate qname whose path goes through a `pub const X = ...;`
    // alias (e.g. `utils.sync.SpinLock` → `utils.sync.spin_lock.SpinLock`)
    // before retrying the lookup. Without this, receiver-chain resolution
    // through any aliased type stays indirect even though the field-type and
    // qname-index entries are present.
    var alias_index = branches.ReexportAliasIndex.init(arena);
    for (aliases) |a| {
        _ = try alias_index.getOrPutValue(a.key, a.target);
    }

    // qname → return-type-qname index. Used by `inferInitType` so a local
    // bound to a call expression (`const port_ref = capability.typedRef(...)
    // orelse ...;`) gets stamped with the call's return type, which the
    // receiver resolver then walks for downstream `port_ref.method(...)`.
    // First-write-wins; functions whose return type didn't reduce to a
    // struct qname are simply omitted (empty value would only confuse the
    // consumer).
    var fn_return_type_index = branches.FnReturnTypeIndex.init(arena);
    for (ast_fns) |af| {
        if (af.return_type_qname.len == 0) continue;
        _ = try fn_return_type_index.getOrPutValue(af.qualified_name, af.return_type_qname);
    }

    // qname → AstFunction lookup. Used by the all-callers-agree pass to
    // (a) find AST-only inline fns with fn-pointer params (the substitution
    //     targets), and
    // (b) resolve `&fnname` / `fnname` argument expressions to a qname.
    var ast_by_qname = std.StringHashMap(*const AstFunction).init(arena);
    for (ast_fns) |*af| {
        _ = try ast_by_qname.getOrPutValue(af.qualified_name, af);
    }

    // ── all-callers-agree fn-pointer parameter substitution ─────────────
    //
    // For each AST-only inline fn whose proto declares one or more
    // `*const fn (...)` parameters, scan every call site across the
    // kernel. If every caller passes the same `&fnname` for a given
    // parameter position, record the binding. Otherwise leave it
    // unbound — emitCall falls through to the indirect synth path.
    //
    // Resolution caveats:
    //   * Args passed via struct fields, slice indexing, or comptime
    //     dispatch are dropped — only direct `&fnname` / `fnname` arg
    //     expressions are resolved.
    //   * Per-call-site precision is not implemented (different callers
    //     passing different fns leave the param indirect). The kEntry
    //     pattern has a single caller so v1 handles it.
    var fnptr_stats: FnPtrStats = .{};
    const param_bindings_by_fn = try buildParamBindings(
        arena,
        functions,
        ast_fns,
        file_asts,
        &ast_by_qname,
        &qname_index,
        &fnptr_stats,
    );

    std.debug.print(
        "ast-only fns with fn-ptr params: {d} (resolved fn-ptr params: {d}/{d})\n",
        .{ fnptr_stats.targets, fnptr_stats.resolved_params, fnptr_stats.total_fn_ptr_params },
    );

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

        // Param-binding lookup: only AST-only inline fns with fn-pointer
        // params can have a binding, and only when every call site agrees.
        // The map is populated in a prior all-callers-agree pass.
        const pb_opt: ?*const branches.ParamBindings = blk: {
            const entry = param_bindings_by_fn.get(f.id) orelse break :blk null;
            break :blk entry;
        };

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
            &struct_type_index,
            af.receiver_name,
            af.receiver_type,
            pb_opt,
            &alias_index,
            &fn_return_type_index,
        ) catch &.{};
    }
}

// ─────────────────────────────────────────────────────── fn-ptr param bindings
//
// All-callers-agree fn-pointer parameter substitution. For each AST-only
// inline fn whose proto declares one or more `*const fn (...)` parameters,
// scan every call site across the kernel. If every caller passes the same
// `&fnname` for a given parameter position, record the binding so the inline
// body's call to that param can be resolved as a direct call to the bound fn.
//
// Resolution caveats:
//   * Args passed via struct fields, slice indexing, or comptime dispatch
//     are dropped — only direct `&fnname` / `fnname` arg expressions are
//     resolved.
//   * Per-call-site precision is not implemented: different callers passing
//     different fns leave the param indirect rather than materializing a
//     per-site intra. The kEntry pattern has a single caller.

const FnPtrStats = struct {
    /// Number of AST-only inline fns with at least one fn-pointer param.
    targets: usize = 0,
    /// Number of fn-ptr params that all-callers-agreed on a single bound qname.
    resolved_params: usize = 0,
    /// Sum of fn-pointer params across every target. Upper bound on
    /// `resolved_params`.
    total_fn_ptr_params: usize = 0,
};

const ParamAgreement = struct {
    /// First-seen resolved qname for this param index across the kernel's
    /// call sites. Empty means we haven't observed an agreement-eligible
    /// call yet.
    qname: []const u8 = "",
    /// Two callers passed conflicting values — substitution is disabled.
    /// Once true, further calls don't update qname.
    disagreed: bool = false,
    /// We encountered a call we couldn't resolve (struct-field arg, indexed
    /// expression, comptime-formed value). Treated as disagreement: better
    /// to under-substitute than substitute against unverified callers.
    saw_unresolvable: bool = false,
};

const TargetAgreement = struct {
    af: *const AstFunction,
    fn_id: types.FnId,
    /// One slot per parameter index; only fn-ptr params are inspected, but
    /// the slice is full-length so positional access aligns with
    /// `target.params[i]`.
    params: []ParamAgreement,
};

fn buildParamBindings(
    arena: std.mem.Allocator,
    functions: []types.Function,
    ast_fns: []const AstFunction,
    file_asts: []const FileAst,
    ast_by_qname: *std.StringHashMap(*const AstFunction),
    qname_index: *branches.QNameIndex,
    stats: *FnPtrStats,
) !std.AutoHashMap(types.FnId, *branches.ParamBindings) {
    _ = ast_fns;
    var out = std.AutoHashMap(types.FnId, *branches.ParamBindings).init(arena);

    // Identify substitution targets: AST-only fns with fn-pointer params.
    var targets_by_qname = std.StringHashMap(*TargetAgreement).init(arena);
    for (functions) |*f| {
        if (!f.is_ast_only) continue;
        const af = ast_by_qname.get(f.name) orelse continue;
        if (af.params.len == 0) continue;
        var any_fn_ptr = false;
        for (af.params) |p| {
            if (p.is_fn_ptr) {
                any_fn_ptr = true;
                stats.total_fn_ptr_params += 1;
            }
        }
        if (!any_fn_ptr) continue;

        const ta = try arena.create(TargetAgreement);
        const params_slice = try arena.alloc(ParamAgreement, af.params.len);
        for (params_slice) |*pa| pa.* = .{};
        ta.* = .{ .af = af, .fn_id = f.id, .params = params_slice };
        try targets_by_qname.put(f.name, ta);
        stats.targets += 1;
    }
    if (targets_by_qname.count() == 0) return out;

    // Walk every file's tree to find calls into the targets.
    for (file_asts) |*fa| {
        try walkFileForTargetCalls(arena, fa, &targets_by_qname, ast_by_qname, qname_index);
    }

    // Promote agreed-on params into ParamBindings entries.
    var it = targets_by_qname.iterator();
    while (it.next()) |entry| {
        const ta = entry.value_ptr.*;
        const bindings = try arena.create(branches.ParamBindings);
        bindings.* = branches.ParamBindings.init(arena);
        var any_resolved = false;
        for (ta.params, 0..) |pa, idx| {
            if (!ta.af.params[idx].is_fn_ptr) continue;
            if (pa.disagreed or pa.saw_unresolvable) continue;
            if (pa.qname.len == 0) continue;
            try bindings.put(ta.af.params[idx].name, pa.qname);
            stats.resolved_params += 1;
            any_resolved = true;
        }
        if (any_resolved) {
            try out.put(ta.fn_id, bindings);
        }
    }
    return out;
}

/// Walk every node in `fa.tree` looking for call expressions. For each call
/// whose fn_expr resolves to a target qname, slice the args at the target's
/// fn-pointer parameter positions and update each ParamAgreement.
fn walkFileForTargetCalls(
    arena: std.mem.Allocator,
    fa: *const FileAst,
    targets: *const std.StringHashMap(*TargetAgreement),
    ast_by_qname: *const std.StringHashMap(*const AstFunction),
    qname_index: *const branches.QNameIndex,
) !void {
    const tree = fa.tree;
    const root_decls = tree.rootDecls();
    var queue = std.ArrayList(std.zig.Ast.Node.Index){};
    defer queue.deinit(arena);
    for (root_decls) |d| try queue.append(arena, d);

    while (queue.pop()) |node| {
        const tag = tree.nodeTag(node);
        switch (tag) {
            .call, .call_comma, .call_one, .call_one_comma => {
                try handleCallForTargets(arena, fa, node, targets, ast_by_qname, qname_index);
            },
            else => {},
        }
        // Always enqueue children — calls can be nested arbitrarily.
        try enqueueChildren(arena, tree, node, &queue);
    }
}

/// For one call expression, if its fn_expr resolves to a target qname,
/// inspect the args at fn-pointer parameter positions and update agreements.
fn handleCallForTargets(
    arena: std.mem.Allocator,
    fa: *const FileAst,
    node: std.zig.Ast.Node.Index,
    targets: *const std.StringHashMap(*TargetAgreement),
    ast_by_qname: *const std.StringHashMap(*const AstFunction),
    qname_index: *const branches.QNameIndex,
) !void {
    var buf: [1]std.zig.Ast.Node.Index = undefined;
    const call = fa.tree.fullCall(&buf, node) orelse return;

    const target_qname = resolveCallTargetQname(arena, fa, call.ast.fn_expr) orelse return;
    if (qname_index.get(target_qname) == null) return;
    const ta = targets.get(target_qname) orelse return;

    // For each fn-pointer param, find the matching arg by position and
    // resolve it to a qname. Args beyond the param count are silently flagged
    // unresolvable (varargs / Zig's call-with-extra).
    for (ta.af.params, 0..) |p, idx| {
        if (!p.is_fn_ptr) continue;
        if (idx >= call.ast.params.len) {
            ta.params[idx].saw_unresolvable = true;
            continue;
        }
        const arg_node = call.ast.params[idx];
        const arg_qname = resolveArgToQname(arena, fa, arg_node, ast_by_qname, qname_index);
        if (arg_qname == null) {
            ta.params[idx].saw_unresolvable = true;
            continue;
        }
        const q = arg_qname.?;
        if (ta.params[idx].qname.len == 0) {
            ta.params[idx].qname = q;
        } else if (!std.mem.eql(u8, ta.params[idx].qname, q)) {
            ta.params[idx].disagreed = true;
        }
    }
}

/// Resolve a call's fn_expr to a global qname using the same rules as
/// branches.resolveByImports (bare ident → same-file top-level fn or
/// import-table mapping; dotted chain → import-prefixed qname). Returns null
/// on any shape we don't handle — receiver methods, indexed expressions, etc.
fn resolveCallTargetQname(
    arena: std.mem.Allocator,
    fa: *const FileAst,
    fn_expr: std.zig.Ast.Node.Index,
) ?[]const u8 {
    const tree = fa.tree;
    const tag = tree.nodeTag(fn_expr);
    if (tag == .identifier) {
        const ident = nodeTokenSliceLocal(tree, fn_expr);
        if (ident.len == 0) return null;
        const file_mod = filePathToDottedModuleLocal(arena, fa.file) catch return null;
        if (file_mod.len > 0) {
            return std.fmt.allocPrint(arena, "{s}.{s}", .{ file_mod, ident }) catch null;
        }
        if (fa.imports.get(ident)) |resolved| return arena.dupe(u8, resolved) catch null;
        return null;
    }
    if (tag != .field_access) return null;
    const chain = nodeChainSliceLocal(tree, fn_expr) orelse return null;
    const dot = std.mem.indexOfScalar(u8, chain, '.') orelse return null;
    const head = chain[0..dot];
    const tail = chain[dot + 1 ..];
    if (tail.len == 0) return null;
    const resolved_head = fa.imports.get(head) orelse return null;
    if (std.mem.eql(u8, resolved_head, "std")) {
        return arena.dupe(u8, tail) catch null;
    }
    return std.fmt.allocPrint(arena, "{s}.{s}", .{ resolved_head, tail }) catch null;
}

/// Resolve an argument expression to a function qname when it has the shape
/// `&fn` or a bare identifier referring to a function. Other shapes return
/// null (the caller flags the target's param as unresolvable).
fn resolveArgToQname(
    arena: std.mem.Allocator,
    fa: *const FileAst,
    arg_node: std.zig.Ast.Node.Index,
    ast_by_qname: *const std.StringHashMap(*const AstFunction),
    qname_index: *const branches.QNameIndex,
) ?[]const u8 {
    const tree = fa.tree;
    var node = arg_node;
    // Peel `&expr` (and the unusual `&&expr`).
    while (tree.nodeTag(node) == .address_of) {
        node = tree.nodeData(node).node;
    }
    const tag = tree.nodeTag(node);
    if (tag == .identifier) {
        const ident = nodeTokenSliceLocal(tree, node);
        if (ident.len == 0) return null;
        const file_mod = filePathToDottedModuleLocal(arena, fa.file) catch return null;
        if (file_mod.len > 0) {
            const cand = std.fmt.allocPrint(arena, "{s}.{s}", .{ file_mod, ident }) catch return null;
            if (qname_index.contains(cand) or ast_by_qname.contains(cand)) return cand;
        }
        if (fa.imports.get(ident)) |resolved| {
            const cand = arena.dupe(u8, resolved) catch return null;
            if (qname_index.contains(cand) or ast_by_qname.contains(cand)) return cand;
        }
        return null;
    }
    if (tag == .field_access) {
        const chain = nodeChainSliceLocal(tree, node) orelse return null;
        const dot = std.mem.indexOfScalar(u8, chain, '.') orelse return null;
        const head = chain[0..dot];
        const tail = chain[dot + 1 ..];
        if (tail.len == 0) return null;
        const resolved_head = fa.imports.get(head) orelse return null;
        const cand = if (std.mem.eql(u8, resolved_head, "std"))
            arena.dupe(u8, tail) catch return null
        else
            std.fmt.allocPrint(arena, "{s}.{s}", .{ resolved_head, tail }) catch return null;
        if (qname_index.contains(cand) or ast_by_qname.contains(cand)) return cand;
        return null;
    }
    return null;
}

/// Enqueue every direct-child Node.Index of `node`. We don't try to be
/// precise about which tags carry which children — the cost of an over-broad
/// probe is negligible and the simpler logic is robust to AST shape changes.
fn enqueueChildren(
    arena: std.mem.Allocator,
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    queue: *std.ArrayList(std.zig.Ast.Node.Index),
) !void {
    const tag = tree.nodeTag(node);
    const data = tree.nodeData(node);
    switch (tag) {
        // Single-child node-only tags.
        .bool_not, .negation, .bit_not, .negation_wrap, .address_of, .@"try",
        .optional_type, .@"suspend", .@"resume", .@"nosuspend", .@"comptime",
        .deref, .@"defer" => try queue.append(arena, data.node),

        .@"return" => if (data.opt_node.unwrap()) |c| try queue.append(arena, c),
        .@"break" => if (data.opt_token_and_opt_node[1].unwrap()) |c| try queue.append(arena, c),

        // Two-child node_and_node forms.
        .@"catch",
        .equal_equal, .bang_equal,
        .less_than, .greater_than, .less_or_equal, .greater_or_equal,
        .assign_mul, .assign_div, .assign_mod, .assign_add, .assign_sub,
        .assign_shl, .assign_shl_sat, .assign_shr,
        .assign_bit_and, .assign_bit_xor, .assign_bit_or,
        .assign_mul_wrap, .assign_add_wrap, .assign_sub_wrap,
        .assign_mul_sat, .assign_add_sat, .assign_sub_sat, .assign,
        .merge_error_sets,
        .mul, .div, .mod, .array_mult,
        .mul_wrap, .mul_sat, .add, .sub, .array_cat,
        .add_wrap, .sub_wrap, .add_sat, .sub_sat,
        .shl, .shl_sat, .shr,
        .bit_and, .bit_xor, .bit_or,
        .@"orelse", .bool_and, .bool_or,
        .slice_open, .array_access, .array_init_one, .array_init_one_comma,
        .switch_range, .error_union, .array_type, .fn_decl => {
            try queue.append(arena, data.node_and_node[0]);
            try queue.append(arena, data.node_and_node[1]);
        },

        .for_range, .struct_init_one, .struct_init_one_comma => {
            try queue.append(arena, data.node_and_opt_node[0]);
            if (data.node_and_opt_node[1].unwrap()) |c| try queue.append(arena, c);
        },

        .field_access, .unwrap_optional, .grouped_expression => {
            try queue.append(arena, data.node_and_token[0]);
        },

        .builtin_call_two, .builtin_call_two_comma,
        .array_init_dot_two, .array_init_dot_two_comma,
        .struct_init_dot_two, .struct_init_dot_two_comma => {
            const a, const b = data.opt_node_and_opt_node;
            if (a.unwrap()) |c| try queue.append(arena, c);
            if (b.unwrap()) |c| try queue.append(arena, c);
        },
        .builtin_call, .builtin_call_comma,
        .array_init_dot, .array_init_dot_comma,
        .struct_init_dot, .struct_init_dot_comma => {
            const slice = tree.extraDataSlice(data.extra_range, std.zig.Ast.Node.Index);
            for (slice) |c| try queue.append(arena, c);
        },

        .block, .block_semicolon, .block_two, .block_two_semicolon => {
            var buf: [2]std.zig.Ast.Node.Index = undefined;
            const stmts = tree.blockStatements(&buf, node) orelse return;
            for (stmts) |s| try queue.append(arena, s);
        },

        .if_simple => {
            const lhs, const rhs = data.node_and_node;
            try queue.append(arena, lhs);
            try queue.append(arena, rhs);
        },
        .@"if" => {
            const cond, const extra_idx = data.node_and_extra;
            try queue.append(arena, cond);
            const extra = tree.extraData(extra_idx, std.zig.Ast.Node.If);
            try queue.append(arena, extra.then_expr);
            try queue.append(arena, extra.else_expr);
        },

        .while_simple, .while_cont, .@"while" => {
            const w = tree.fullWhile(node).?;
            try queue.append(arena, w.ast.cond_expr);
            try queue.append(arena, w.ast.then_expr);
            if (w.ast.cont_expr.unwrap()) |c| try queue.append(arena, c);
            if (w.ast.else_expr.unwrap()) |c| try queue.append(arena, c);
        },
        .for_simple, .@"for" => {
            const f = tree.fullFor(node).?;
            for (f.ast.inputs) |c| try queue.append(arena, c);
            try queue.append(arena, f.ast.then_expr);
            if (f.ast.else_expr.unwrap()) |c| try queue.append(arena, c);
        },

        .@"switch", .switch_comma => {
            const sw = tree.fullSwitch(node).?;
            try queue.append(arena, sw.ast.condition);
            for (sw.ast.cases) |c| try queue.append(arena, c);
        },
        .switch_case_one, .switch_case_inline_one => {
            const v, const target = data.opt_node_and_node;
            if (v.unwrap()) |c| try queue.append(arena, c);
            try queue.append(arena, target);
        },
        .switch_case, .switch_case_inline => {
            const extra, const target = data.extra_and_node;
            const sub = tree.extraData(extra, std.zig.Ast.Node.SubRange);
            const slice = tree.extraDataSlice(sub, std.zig.Ast.Node.Index);
            for (slice) |c| try queue.append(arena, c);
            try queue.append(arena, target);
        },

        .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
            const vd = tree.fullVarDecl(node) orelse return;
            if (vd.ast.init_node.unwrap()) |c| try queue.append(arena, c);
        },

        .call, .call_comma, .call_one, .call_one_comma => {
            var buf: [1]std.zig.Ast.Node.Index = undefined;
            const call = tree.fullCall(&buf, node) orelse return;
            try queue.append(arena, call.ast.fn_expr);
            for (call.ast.params) |p| try queue.append(arena, p);
        },

        .slice => {
            const sliced, const extra = data.node_and_extra;
            try queue.append(arena, sliced);
            const s = tree.extraData(extra, std.zig.Ast.Node.Slice);
            try queue.append(arena, s.start);
            try queue.append(arena, s.end);
        },
        .slice_sentinel => {
            const sliced, const extra = data.node_and_extra;
            try queue.append(arena, sliced);
            const s = tree.extraData(extra, std.zig.Ast.Node.SliceSentinel);
            try queue.append(arena, s.start);
            if (s.end.unwrap()) |c| try queue.append(arena, c);
            try queue.append(arena, s.sentinel);
        },
        .array_init, .array_init_comma, .struct_init, .struct_init_comma => {
            const ty, const extra = data.node_and_extra;
            try queue.append(arena, ty);
            const sub = tree.extraData(extra, std.zig.Ast.Node.SubRange);
            const slice = tree.extraDataSlice(sub, std.zig.Ast.Node.Index);
            for (slice) |c| try queue.append(arena, c);
        },

        .assign_destructure => {
            _, const init_node = data.extra_and_node;
            try queue.append(arena, init_node);
        },

        else => {},
    }
}

/// Slice `node` if it's an identifier; empty slice on any other tag.
fn nodeTokenSliceLocal(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) []const u8 {
    if (tree.nodeTag(node) != .identifier) return "";
    const tok = tree.nodeMainToken(node);
    return tree.tokenSlice(tok);
}

/// Slice the source for an identifier or `.field_access` chain. Returns null
/// for any other tag.
fn nodeChainSliceLocal(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) ?[]const u8 {
    const tag = tree.nodeTag(node);
    if (tag != .field_access and tag != .identifier) return null;
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    const start = tree.tokenStart(first);
    const last_start = tree.tokenStart(last);
    const last_slice = tree.tokenSlice(last);
    const end: usize = @as(usize, last_start) + last_slice.len;
    if (end <= start or end > tree.source.len) return null;
    return tree.source[start..end];
}

/// Map an absolute file path to the dotted module-path form the AST walker
/// emits as the qname prefix. Mirrors `walker.filePathToModulePath`.
fn filePathToDottedModuleLocal(arena: std.mem.Allocator, abs_file: []const u8) ![]const u8 {
    var rel: []const u8 = abs_file;
    const zig_std_prefix = "/usr/lib/zig/std/";
    const zig_root_prefix = "/usr/lib/zig/";
    if (std.mem.startsWith(u8, rel, zig_std_prefix)) {
        rel = rel[zig_std_prefix.len..];
    } else if (std.mem.startsWith(u8, rel, zig_root_prefix)) {
        rel = rel[zig_root_prefix.len..];
    } else if (std.mem.indexOf(u8, rel, "/kernel/")) |i| {
        rel = rel[i + "/kernel/".len ..];
    } else if (std.mem.startsWith(u8, rel, "kernel/")) {
        rel = rel["kernel/".len..];
    } else {
        return "";
    }
    if (std.mem.endsWith(u8, rel, ".zig")) {
        rel = rel[0 .. rel.len - ".zig".len];
    }
    const out = try arena.dupe(u8, rel);
    for (out) |*c| {
        if (c.* == '/') c.* = '.';
    }
    return out;
}
