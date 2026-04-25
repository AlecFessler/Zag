// IR ↔ AST join + Graph builder.
//
// Combines an IrGraph (mangled fn names + call edges from LLVM IR) with the
// AstFunction list emitted by ast/walker.zig, producing a Graph the server
// can render. The join key is `(absolute_file, line)` — IR's def_loc and
// AST's `line_start` should agree on the line of the `fn` keyword.
//
// For each IR function with a successful AST match, `display_name` is set to
// the AST's qualified name (e.g. `memory.pmm.alloc`). On miss we fall back
// to the IR mangled name, which Zig already emits in a near-readable form.
//
// Each EnrichedEdge gets `target_name` filled in from the resolved target
// function's display name when possible.
//
// Entry-point heuristic: same path-suffix scan that lived inline in main.zig
// in phase 1, moved here to keep main.zig small.

const std = @import("std");

const ast = @import("ast/index.zig");
const types = @import("types.zig");

const AstFunction = ast.AstFunction;

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
    return try buildGraphWithStats(arena, ir_graph, ast_fns, &stats);
}

pub fn buildGraphWithStats(
    arena: std.mem.Allocator,
    ir_graph: types.IrGraph,
    ast_fns: []const AstFunction,
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

    for (ast_fns) |*af| {
        const resolved = try resolvePath(arena, &realpath_cache, af.file);
        const key = try std.fmt.allocPrint(arena, "{s}:{d}", .{ resolved, af.line_start });
        // Last-write-wins on collision; collisions would be e.g. two fns
        // declared on the same line, which Zig disallows. Practically this
        // never happens.
        try ast_index.put(key, af);
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

    try applyEntryHeuristic(functions);

    var entry_points = std.ArrayList(types.EntryPoint){};
    for (functions) |f| {
        if (f.is_entry) {
            try entry_points.append(arena, .{
                .fn_id = f.id,
                .kind = f.entry_kind orelse .manual,
                .label = f.name,
            });
        }
    }

    stats_out.* = .{ .ir_total = ir_graph.functions.len, .matched = matched };

    return .{
        .functions = functions,
        .entry_points = try entry_points.toOwnedSlice(arena),
    };
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

/// Heuristic entry-point detection. Real auto-discovery is phase 4; this is
/// just enough to give the frontend something to render. Mark every function
/// whose def_loc.file ends with one of a small set of dispatch/exception
/// files; if that yields nothing, fall back to a name-substring scan.
fn applyEntryHeuristic(functions: []types.Function) !void {
    const path_suffixes = [_][]const u8{
        "kernel/syscall/dispatch.zig",
        "kernel/arch/x64/exceptions.zig",
        "kernel/arch/x64/idt.zig",
    };

    var marked: usize = 0;
    for (functions) |*f| {
        for (path_suffixes) |suffix| {
            if (std.mem.endsWith(u8, f.def_loc.file, suffix)) {
                f.is_entry = true;
                f.entry_kind = entryKindForFile(f.def_loc.file);
                marked += 1;
                break;
            }
        }
    }
    if (marked > 0) return;

    // Fallback — pick up to 5 by name substring.
    const name_substrs = [_][]const u8{ "entry", "syscall", "handler" };
    var picked: usize = 0;
    for (functions) |*f| {
        if (picked >= 5) break;
        for (name_substrs) |needle| {
            if (std.mem.indexOf(u8, f.mangled, needle) != null) {
                f.is_entry = true;
                f.entry_kind = .manual;
                picked += 1;
                break;
            }
        }
    }
}

fn entryKindForFile(file: []const u8) types.EntryKind {
    if (std.mem.endsWith(u8, file, "kernel/syscall/dispatch.zig")) return .syscall;
    if (std.mem.endsWith(u8, file, "kernel/arch/x64/exceptions.zig")) return .trap;
    if (std.mem.endsWith(u8, file, "kernel/arch/x64/idt.zig")) return .irq;
    return .manual;
}
