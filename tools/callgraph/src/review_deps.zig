//! Computes the canonical dep set for a review item.
//!
//! Same algorithm the web view uses for dep-highlighting (def_deps
//! extension) plus the caller/callee walks the existing callgraph_*
//! tools expose. Centralized here so both the MCP `_deps` call and any
//! future GUI surface read from the same source of truth.
//!
//! Returned entries include qualified name + def location + a 1-line
//! context summary (the call site for callers/callees, the
//! def-dependency reference for readers/writers). Names are extracted
//! into the `Item.deps_required` slice for the gate; the rich entries
//! are what the agent sees as the response payload.

const std = @import("std");

const review_store = @import("review_store.zig");
const types = @import("types.zig");

const Item = review_store.Item;
const DepsKind = review_store.DepsKind;

pub const DepEntry = struct {
    qualified_name: []const u8,
    file: []const u8,
    line: u32,
    /// Short why-this-dep-matters string. For `callers`/`callees` this
    /// is the call site (`<file>:<line>`); for `readers_writers` it's
    /// the depending function's location. Always present so the MCP
    /// response is uniform.
    summary: []const u8,
};

/// Compute the dep set for `item` against `graph`. Returns an empty
/// slice for items whose `deps_kind` is `none` (orphan hunks, trivial
/// changes). Returns an empty slice for symbol items whose `qualified_name`
/// can't be resolved against the graph (defensive — shouldn't happen
/// when classifier and graph come from the same commit).
///
/// All strings are allocated in `alloc` (typically a request-scoped arena).
pub fn computeDeps(
    alloc: std.mem.Allocator,
    item: *const Item,
    graph: *const types.Graph,
) ![]DepEntry {
    if (item.deps_kind == .none) return &.{};
    const qname = item.qualified_name orelse return &.{};

    return switch (item.deps_kind) {
        .none => &.{},
        .callers => try collectCallers(alloc, qname, graph),
        .callers_callees => try collectCallersAndCallees(alloc, qname, graph),
        .readers_writers => try collectReadersWriters(alloc, qname, graph),
        // v1: added/removed degenerate to caller-side analysis. Symbol_added
        // looks like a sig change in the new graph (callers may not exist
        // yet, but call_sites = future callers — empty for now). Symbol_removed
        // requires the OLD graph, which we don't load — degrade to empty.
        .call_sites => try collectCallers(alloc, qname, graph),
        .prior_callers => &.{},
    };
}

/// Helper: pull out just the qualified-name list from a dep set, in the
/// order the entries appear. The MCP `_deps` call uses this to compute
/// the new `Item.deps_required` (after merging with the prior list to
/// preserve stickiness).
pub fn extractNames(alloc: std.mem.Allocator, deps: []const DepEntry) ![][]const u8 {
    var out = try alloc.alloc([]const u8, deps.len);
    for (deps, 0..) |d, i| out[i] = d.qualified_name;
    return out;
}

// ---- Internal --------------------------------------------------------------

fn findFnByQname(graph: *const types.Graph, qname: []const u8) ?*const types.Function {
    for (graph.functions) |*fn_ptr| {
        if (std.mem.eql(u8, fn_ptr.name, qname)) return fn_ptr;
        if (std.mem.eql(u8, fn_ptr.mangled, qname)) return fn_ptr;
    }
    return null;
}

fn findDefByQname(graph: *const types.Graph, qname: []const u8) ?*const types.Definition {
    for (graph.definitions) |*def_ptr| {
        if (std.mem.eql(u8, def_ptr.qualified_name, qname)) return def_ptr;
    }
    return null;
}

/// Walk every function's `callees` list, collect the ones that target
/// `qname`. Each call site produces one entry — callers that call
/// `qname` from multiple sites get one entry per site (the agent
/// genuinely needs to look at each one). Compiler-synthesized fns
/// (names starting with `__zig_`) are skipped — they have no source
/// location and aren't reviewable.
fn collectCallers(
    alloc: std.mem.Allocator,
    qname: []const u8,
    graph: *const types.Graph,
) ![]DepEntry {
    const target = findFnByQname(graph, qname) orelse return &.{};

    var out = std.ArrayList(DepEntry){};
    for (graph.functions) |*fn_ptr| {
        if (isFilteredDep(fn_ptr.name)) continue;
        for (fn_ptr.callees) |edge| {
            const matches = (edge.to != null and edge.to.? == target.id) or
                (edge.target_name != null and std.mem.eql(u8, edge.target_name.?, qname));
            if (!matches) continue;
            try out.append(alloc, .{
                .qualified_name = fn_ptr.name,
                .file = fn_ptr.def_loc.file,
                .line = fn_ptr.def_loc.line,
                .summary = try std.fmt.allocPrint(alloc, "calls {s} at {s}:{d}", .{
                    qname, edge.site.file, edge.site.line,
                }),
            });
        }
    }
    return try out.toOwnedSlice(alloc);
}

/// True for symbols that should not appear in deps_required: compiler-
/// synthesized helpers (no source location → would crash the viewer
/// before render's guard caught it), and stdlib/builtin/debug.FullPanic
/// leaves that the compiler inserts for safety checks. The latter are
/// cold branches that produce zero ripple insight; forcing the agent to
/// view debug.FullPanic.invalidEnumValue per review is busywork.
///
/// Same prefix conventions the trace tool already collapses with `%`
/// (debug.*) and `=` (std./builtin.*) markers — so the review tool
/// stays consistent with the user's mental model.
fn isFilteredDep(name: []const u8) bool {
    if (std.mem.startsWith(u8, name, "__zig_")) return true;
    if (std.mem.startsWith(u8, name, "std.")) return true;
    if (std.mem.startsWith(u8, name, "builtin.")) return true;
    if (std.mem.startsWith(u8, name, "debug.")) return true;
    return false;
}

/// Callers + the target's own callees. Direct calls only (no indirect /
/// vtable) — those require human judgment to enumerate, and the agent
/// can't usefully verify ripple through them anyway.
fn collectCallersAndCallees(
    alloc: std.mem.Allocator,
    qname: []const u8,
    graph: *const types.Graph,
) ![]DepEntry {
    const target = findFnByQname(graph, qname) orelse return &.{};
    const callers = try collectCallers(alloc, qname, graph);

    var out = std.ArrayList(DepEntry){};
    try out.appendSlice(alloc, callers);

    // Dedup callees by qualified name — a fn that calls bar() in three
    // places is one item to view.
    var seen = std.StringHashMap(void).init(alloc);
    for (target.callees) |edge| {
        const callee_name = blk: {
            if (edge.to) |to_id| {
                for (graph.functions) |*fn_ptr| {
                    if (fn_ptr.id == to_id) break :blk fn_ptr.name;
                }
            }
            if (edge.target_name) |n| break :blk n;
            continue;
        };
        if (isFilteredDep(callee_name)) continue;
        if (seen.contains(callee_name)) continue;
        try seen.put(callee_name, {});
        const callee_fn = findFnByQname(graph, callee_name);
        const file = if (callee_fn) |cf| cf.def_loc.file else edge.site.file;
        const line = if (callee_fn) |cf| cf.def_loc.line else edge.site.line;
        try out.append(alloc, .{
            .qualified_name = callee_name,
            .file = file,
            .line = line,
            .summary = try std.fmt.allocPrint(alloc, "called by {s} at {s}:{d}", .{
                qname, edge.site.file, edge.site.line,
            }),
        });
    }
    return try out.toOwnedSlice(alloc);
}

/// Functions that reference this Definition via the def_deps pass,
/// PLUS the types that contain those functions (heuristic: a method's
/// qname is `<type_qname>.<method>`, so the prefix is its containing
/// type — if that type exists as a Definition, it's added as a type
/// dep). The containing-type rule catches the "ChangedType is used by
/// methods of OtherType, so OtherType is structurally affected" case
/// without needing a separate def-to-def deps pass.
///
/// Type deps are deduped across all matching functions. Function deps
/// come first (in graph order), then types (in first-seen order). The
/// _checkoff gate accepts callgraph_src for function deps and
/// callgraph_type for type deps.
fn collectReadersWriters(
    alloc: std.mem.Allocator,
    qname: []const u8,
    graph: *const types.Graph,
) ![]DepEntry {
    const target = findDefByQname(graph, qname) orelse return &.{};

    var fn_entries = std.ArrayList(DepEntry){};
    var type_entries = std.ArrayList(DepEntry){};
    var seen_types = std.StringHashMap(void).init(alloc);

    for (graph.functions) |*fn_ptr| {
        if (isFilteredDep(fn_ptr.name)) continue;
        var hits = false;
        for (fn_ptr.def_deps) |did| {
            if (did == target.id) {
                hits = true;
                break;
            }
        }
        if (!hits) continue;

        try fn_entries.append(alloc, .{
            .qualified_name = fn_ptr.name,
            .file = fn_ptr.def_loc.file,
            .line = fn_ptr.def_loc.line,
            .summary = try std.fmt.allocPrint(alloc, "uses {s}", .{qname}),
        });

        if (containingType(fn_ptr.name, graph)) |container| {
            // Skip the target itself (a method of the changed type
            // reading its own type isn't a separate dep).
            if (std.mem.eql(u8, container.qualified_name, qname)) continue;
            if (seen_types.contains(container.qualified_name)) continue;
            try seen_types.put(container.qualified_name, {});
            try type_entries.append(alloc, .{
                .qualified_name = container.qualified_name,
                .file = container.file,
                .line = container.line_start,
                .summary = try std.fmt.allocPrint(alloc, "contains methods that use {s}", .{qname}),
            });
        }
    }

    var out = std.ArrayList(DepEntry){};
    try out.appendSlice(alloc, fn_entries.items);
    try out.appendSlice(alloc, type_entries.items);
    return try out.toOwnedSlice(alloc);
}

/// Heuristic: the dotted prefix of a function's qualified name is its
/// containing type's qname (if such a type exists as a Definition).
/// `module.Process.start` → `module.Process`. Returns null when the
/// prefix doesn't resolve to a known Definition.
fn containingType(fn_name: []const u8, graph: *const types.Graph) ?*const types.Definition {
    const last_dot = std.mem.lastIndexOfScalar(u8, fn_name, '.') orelse return null;
    const prefix = fn_name[0..last_dot];
    return findDefByQname(graph, prefix);
}

// ---- Tests -----------------------------------------------------------------

const testing = std.testing;

fn makeFn(
    id: types.FnId,
    name: []const u8,
    file: []const u8,
    line: u32,
    callees: []types.EnrichedEdge,
    def_deps: []const types.DefId,
) types.Function {
    return .{
        .id = id,
        .name = name,
        .mangled = name,
        .def_loc = .{ .file = file, .line = line },
        .callees = callees,
        .def_deps = def_deps,
    };
}

fn makeEdge(to: ?types.FnId, target_name: ?[]const u8, file: []const u8, line: u32) types.EnrichedEdge {
    return .{
        .to = to,
        .target_name = target_name,
        .kind = .direct,
        .site = .{ .file = file, .line = line },
    };
}

fn makeDef(id: types.DefId, qname: []const u8, file: []const u8) types.Definition {
    return .{
        .id = id,
        .name = qname,
        .qualified_name = qname,
        .file = file,
        .line_start = 1,
        .line_end = 5,
        .kind = .struct_,
    };
}

fn mkItem(
    qname: ?[]const u8,
    deps_kind: DepsKind,
) Item {
    return .{
        .id = "test",
        .kind = .symbol_body,
        .deps_kind = deps_kind,
        .file = "x",
        .loc = "x",
        .qualified_name = qname,
    };
}

test "computeDeps: deps_kind=none returns empty" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const g = types.Graph{ .functions = &.{}, .entry_points = &.{}, .definitions = &.{} };
    const it = mkItem(null, .none);
    const got = try computeDeps(a, &it, &g);
    try testing.expectEqual(@as(usize, 0), got.len);
}

test "computeDeps: callers walks every fn's callee list and collects matches" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fn0_callees = [_]types.EnrichedEdge{
        makeEdge(2, null, "src/a.zig", 10),
    };
    var fn1_callees = [_]types.EnrichedEdge{
        makeEdge(2, null, "src/b.zig", 20),
        makeEdge(2, null, "src/b.zig", 25), // same caller, two sites → two entries
    };
    var fn2_callees = [_]types.EnrichedEdge{};
    var fns = [_]types.Function{
        makeFn(0, "a.callerOne", "src/a.zig", 1, &fn0_callees, &.{}),
        makeFn(1, "b.callerTwo", "src/b.zig", 1, &fn1_callees, &.{}),
        makeFn(2, "x.target", "src/x.zig", 1, &fn2_callees, &.{}),
    };
    const g = types.Graph{ .functions = &fns, .entry_points = &.{}, .definitions = &.{} };
    const it = mkItem("x.target", .callers);

    const got = try computeDeps(a, &it, &g);
    try testing.expectEqual(@as(usize, 3), got.len);
    try testing.expectEqualStrings("a.callerOne", got[0].qualified_name);
    try testing.expectEqualStrings("b.callerTwo", got[1].qualified_name);
    try testing.expectEqualStrings("b.callerTwo", got[2].qualified_name);
}

test "computeDeps: callers matches by target_name when to is null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fn0_callees = [_]types.EnrichedEdge{
        makeEdge(null, "x.target", "src/a.zig", 10),
    };
    var fn1_callees = [_]types.EnrichedEdge{};
    var fns = [_]types.Function{
        makeFn(0, "a.caller", "src/a.zig", 1, &fn0_callees, &.{}),
        makeFn(1, "x.target", "src/x.zig", 1, &fn1_callees, &.{}),
    };
    const g = types.Graph{ .functions = &fns, .entry_points = &.{}, .definitions = &.{} };
    const it = mkItem("x.target", .callers);

    const got = try computeDeps(a, &it, &g);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("a.caller", got[0].qualified_name);
}

test "computeDeps: callers_callees combines callers with target's own callees, deduped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var caller_callees = [_]types.EnrichedEdge{
        makeEdge(1, null, "src/a.zig", 10),
    };
    var target_callees = [_]types.EnrichedEdge{
        makeEdge(2, null, "src/x.zig", 20),
        makeEdge(2, null, "src/x.zig", 30), // dedup: same callee, two sites → one entry
        makeEdge(3, null, "src/x.zig", 40),
    };
    var leaf_callees = [_]types.EnrichedEdge{};
    var fns = [_]types.Function{
        makeFn(0, "a.caller", "src/a.zig", 1, &caller_callees, &.{}),
        makeFn(1, "x.target", "src/x.zig", 1, &target_callees, &.{}),
        makeFn(2, "y.helper", "src/y.zig", 1, &leaf_callees, &.{}),
        makeFn(3, "z.other", "src/z.zig", 1, &leaf_callees, &.{}),
    };
    const g = types.Graph{ .functions = &fns, .entry_points = &.{}, .definitions = &.{} };
    const it = mkItem("x.target", .callers_callees);

    const got = try computeDeps(a, &it, &g);
    try testing.expectEqual(@as(usize, 3), got.len);
    try testing.expectEqualStrings("a.caller", got[0].qualified_name);
    try testing.expectEqualStrings("y.helper", got[1].qualified_name);
    try testing.expectEqualStrings("z.other", got[2].qualified_name);
}

test "computeDeps: readers_writers collects fns with def_id in def_deps" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const def_deps_a = [_]types.DefId{ 5, 10, 99 };
    const def_deps_b = [_]types.DefId{42};
    const def_deps_c = [_]types.DefId{ 1, 2, 99 };
    var no_callees = [_]types.EnrichedEdge{};
    var fns = [_]types.Function{
        makeFn(0, "a.readerA", "src/a.zig", 1, &no_callees, &def_deps_a),
        makeFn(1, "b.unrelated", "src/b.zig", 1, &no_callees, &def_deps_b),
        makeFn(2, "c.readerC", "src/c.zig", 1, &no_callees, &def_deps_c),
    };
    var defs = [_]types.Definition{makeDef(99, "x.SomeType", "src/x.zig")};
    const g = types.Graph{ .functions = &fns, .entry_points = &.{}, .definitions = &defs };
    const it = mkItem("x.SomeType", .readers_writers);

    const got = try computeDeps(a, &it, &g);
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualStrings("a.readerA", got[0].qualified_name);
    try testing.expectEqualStrings("c.readerC", got[1].qualified_name);
}

test "computeDeps: missing qname (orphan hunk in odd state) returns empty" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const g = types.Graph{ .functions = &.{}, .entry_points = &.{}, .definitions = &.{} };
    const it = mkItem(null, .callers);
    const got = try computeDeps(a, &it, &g);
    try testing.expectEqual(@as(usize, 0), got.len);
}

test "computeDeps: unresolved qname returns empty (no panic)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const g = types.Graph{ .functions = &.{}, .entry_points = &.{}, .definitions = &.{} };
    const it = mkItem("missing.symbol", .callers);
    const got = try computeDeps(a, &it, &g);
    try testing.expectEqual(@as(usize, 0), got.len);
}

test "computeDeps: prior_callers returns empty in v1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const g = types.Graph{ .functions = &.{}, .entry_points = &.{}, .definitions = &.{} };
    const it = mkItem("anything", .prior_callers);
    const got = try computeDeps(a, &it, &g);
    try testing.expectEqual(@as(usize, 0), got.len);
}

test "computeDeps: readers_writers also includes containing types of reader fns" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Layout:
    //   module.Process — type definition
    //   module.Process.start — method that uses module.Config
    //   module.Process.stop  — method that uses module.Config (same containing type, dedup)
    //   module.Helper.fly    — fn whose containing type "module.Helper" is NOT a defined type
    //   module.Config — the changed type
    const def_deps_uses_config = [_]types.DefId{42};
    var no_callees = [_]types.EnrichedEdge{};
    var fns = [_]types.Function{
        makeFn(0, "module.Process.start", "src/p.zig", 1, &no_callees, &def_deps_uses_config),
        makeFn(1, "module.Process.stop", "src/p.zig", 1, &no_callees, &def_deps_uses_config),
        makeFn(2, "module.Helper.fly", "src/h.zig", 1, &no_callees, &def_deps_uses_config),
    };
    var defs = [_]types.Definition{
        makeDef(42, "module.Config", "src/c.zig"),
        makeDef(7, "module.Process", "src/p.zig"),
        // module.Helper intentionally NOT defined — the heuristic should
        // skip the type dep when the prefix doesn't resolve.
    };
    const g = types.Graph{ .functions = &fns, .entry_points = &.{}, .definitions = &defs };
    const it = mkItem("module.Config", .readers_writers);

    const got = try computeDeps(a, &it, &g);
    // 3 function deps (start, stop, fly) + 1 type dep (Process; Helper undefined skips)
    try testing.expectEqual(@as(usize, 4), got.len);
    // Function deps come first, in graph order.
    try testing.expectEqualStrings("module.Process.start", got[0].qualified_name);
    try testing.expectEqualStrings("module.Process.stop", got[1].qualified_name);
    try testing.expectEqualStrings("module.Helper.fly", got[2].qualified_name);
    // Type dep is deduped (Process appeared twice via start+stop, dedup → one entry).
    try testing.expectEqualStrings("module.Process", got[3].qualified_name);
}

test "computeDeps: readers_writers skips the changed type itself when its own methods read it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // module.Config — the changed type, has its own method that uses it.
    // Result should include the method (function dep) but NOT
    // module.Config as a type dep — that's circular noise.
    const def_deps_uses_config = [_]types.DefId{42};
    var no_callees = [_]types.EnrichedEdge{};
    var fns = [_]types.Function{
        makeFn(0, "module.Config.validate", "src/c.zig", 10, &no_callees, &def_deps_uses_config),
    };
    var defs = [_]types.Definition{makeDef(42, "module.Config", "src/c.zig")};
    const g = types.Graph{ .functions = &fns, .entry_points = &.{}, .definitions = &defs };
    const it = mkItem("module.Config", .readers_writers);

    const got = try computeDeps(a, &it, &g);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("module.Config.validate", got[0].qualified_name);
}

test "extractNames: pulls qualified_names in order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const deps = [_]DepEntry{
        .{ .qualified_name = "alpha", .file = "f", .line = 1, .summary = "s" },
        .{ .qualified_name = "beta", .file = "f", .line = 2, .summary = "s" },
        .{ .qualified_name = "gamma", .file = "f", .line = 3, .summary = "s" },
    };
    const names = try extractNames(a, &deps);
    try testing.expectEqual(@as(usize, 3), names.len);
    try testing.expectEqualStrings("alpha", names[0]);
    try testing.expectEqualStrings("beta", names[1]);
    try testing.expectEqualStrings("gamma", names[2]);
}
