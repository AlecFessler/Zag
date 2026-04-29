//! Textual call-graph rendering.
//!
//! Shared between the REPL (interactive output) and the HTTP server's
//! `/api/trace` + `/api/fn_source` endpoints (which power the MCP tool
//! surface). Renders a call-tree rooted at one Function as indented text,
//! mirroring the web Trace pane: control-flow blocks (`if/else`, `switch`,
//! `loop`) are kept structurally, debug/stdlib leaves can be folded, and
//! recursion + depth caps are honored so output stays bounded.

const std = @import("std");

const types = @import("types.zig");

const Atom = types.Atom;
const ArmSeq = types.ArmSeq;
const BranchAtom = types.BranchAtom;
const Callee = types.Callee;
const EntryKind = types.EntryKind;
const FnId = types.FnId;
const Function = types.Function;
const Graph = types.Graph;
const LoopAtom = types.LoopAtom;
const SourceLoc = types.SourceLoc;

/// Column at which a function's file:line should align. Falls through to a
/// double-space separator when the leading text is wider.
pub const LOC_COLUMN: usize = 64;

/// One reverse-edge: a call site that targets some function. Populated
/// from each function's `intra` Atom tree (which already has branch/loop
/// calls in addition to top-level direct calls). Used by the `/api/callers`
/// endpoint to answer "who calls X" without a full graph walk per request.
pub const CallerSite = struct {
    /// The function whose body contains the call site.
    from: *const Function,
    /// Source location of the call expression itself.
    site: SourceLoc,
    /// Edge kind from the IR resolver (direct, dispatch, indirect, …).
    kind: types.EdgeKind,
};

pub const Maps = struct {
    by_id: std.AutoHashMap(FnId, *const Function),
    by_name: std.StringHashMap(*const Function),
    /// All Functions sharing each name — the index `by_name` only keeps
    /// one entry per key, so generic-method monomorphizations
    /// (`SlabRef(Port).lock`, `SlabRef(EC).lock`, …) collapse to a
    /// single visible Function under that map. `by_name_multi` keeps
    /// every instantiation so callers-style endpoints can aggregate
    /// across them and report the true call-site count.
    by_name_multi: std.StringHashMap(std.ArrayList(*const Function)),
    /// Reverse-edge index: callee FnId → all known call sites that
    /// reach it. Owned by this Maps; freed in `deinit`.
    callers: std.AutoHashMap(FnId, std.ArrayList(CallerSite)),
    /// Allocator that owns the `callers` lists. Stored so `deinit` can
    /// free each list without a separate allocator argument.
    callers_alloc: std.mem.Allocator,

    pub fn deinit(self: *Maps) void {
        self.by_id.deinit();
        self.by_name.deinit();
        var mit = self.by_name_multi.valueIterator();
        while (mit.next()) |list| list.deinit(self.callers_alloc);
        self.by_name_multi.deinit();
        var it = self.callers.valueIterator();
        while (it.next()) |list| list.deinit(self.callers_alloc);
        self.callers.deinit();
    }
};

pub const Ctx = struct {
    by_id: *const std.AutoHashMap(FnId, *const Function),
    by_name: *const std.StringHashMap(*const Function),
    hide_debug: bool,
    hide_library: bool,
    /// When true, drop `debug.assert`, `debug.FullPanic.*`, and
    /// `builtin.returnError` calls entirely — no trace line at all. These
    /// are 0-signal noise in most investigations (every fallible path has
    /// a `returnError`; every guarded one has an `assert`); folding them
    /// to a `%` or `=` leaf still costs a line per occurrence. Default
    /// true. Pass false when explicitly investigating panic / failure
    /// sites.
    hide_assertions: bool = true,
    /// When true, skip `&<bare_ident>` lines whose target name is a single
    /// identifier (no dots, no parens). Such lines are usually argument
    /// captures or struct-field references that the IR analyzer flagged as
    /// indirect calls but that don't actually resolve to a callsite — they
    /// dominate trace output (~25-35% of lines) without carrying signal.
    /// Real fn-pointer / vtable indirect calls (anything with a dotted or
    /// expression-shaped name) are still rendered.
    hide_ref_captures: bool = true,
    /// Patterns folded as `-` leaves in the trace. Each pattern is either
    /// a literal substring or ends in `.*` to mean "anything starting with
    /// this prefix". Empty when no excludes were requested.
    excludes: []const []const u8 = &.{},
};

/// True when `name` looks like a bare identifier (`self`, `p`, `buckets`),
/// not a real call expression (`foo.bar.baz`, `vt.fp[i]`). Such names usually
/// come from the IR analyzer mis-classifying an argument capture as an
/// indirect call.
pub fn isTrivialRefCapture(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '_';
        if (!ok) return false;
    }
    return true;
}

/// Check whether `name` matches any of the exclude patterns. Patterns
/// ending in `.*` are treated as prefix matches; otherwise substring.
pub fn matchExclude(name: []const u8, patterns: []const []const u8) bool {
    for (patterns) |p| {
        if (p.len == 0) continue;
        if (std.mem.endsWith(u8, p, ".*")) {
            const prefix = p[0 .. p.len - 2];
            if (std.mem.startsWith(u8, name, prefix)) return true;
        } else {
            if (std.mem.indexOf(u8, name, p) != null) return true;
        }
    }
    return false;
}

const RenderError = std.io.Writer.Error || std.mem.Allocator.Error;

/// Empty `Maps` placeholder, used when no graph is loaded for an arch.
/// Safe to `deinit`.
pub fn emptyMaps(gpa: std.mem.Allocator) Maps {
    return .{
        .by_id = std.AutoHashMap(FnId, *const Function).init(gpa),
        .by_name = std.StringHashMap(*const Function).init(gpa),
        .by_name_multi = std.StringHashMap(std.ArrayList(*const Function)).init(gpa),
        .callers = std.AutoHashMap(FnId, std.ArrayList(CallerSite)).init(gpa),
        .callers_alloc = gpa,
    };
}

/// Build `(by_id, by_name, callers)` lookup maps over a graph. Caller
/// owns the returned `Maps` and must call `deinit` when done.
pub fn buildLookups(gpa: std.mem.Allocator, g: *const Graph) !Maps {
    var by_id = std.AutoHashMap(FnId, *const Function).init(gpa);
    errdefer by_id.deinit();
    var by_name = std.StringHashMap(*const Function).init(gpa);
    errdefer by_name.deinit();
    // Multi-value name index. Generic methods compile to one Function
    // per (T,) instantiation but all share the same `name`, so a plain
    // map silently drops all but the last. `by_name_multi` records
    // every Function for each key so /api/callers can aggregate across
    // instantiations.
    var by_name_multi = std.StringHashMap(std.ArrayList(*const Function)).init(gpa);
    errdefer {
        var it = by_name_multi.valueIterator();
        while (it.next()) |list| list.deinit(gpa);
        by_name_multi.deinit();
    }
    for (g.functions) |*f| {
        try by_id.put(f.id, f);
        try by_name.put(f.name, f);
        if (!std.mem.eql(u8, f.mangled, f.name)) {
            try by_name.put(f.mangled, f);
        }
        const gop = try by_name_multi.getOrPut(f.name);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.append(gpa, f);
    }

    // Reverse-edge index. We walk each fn's intra Atom tree (which is the
    // same source the trace uses) so the caller list reflects exactly what
    // would render in /api/trace pointing to the target.
    var callers = std.AutoHashMap(FnId, std.ArrayList(CallerSite)).init(gpa);
    errdefer {
        var it = callers.valueIterator();
        while (it.next()) |list| list.deinit(gpa);
        callers.deinit();
    }
    for (g.functions) |*f| {
        try collectIntraCallers(gpa, &callers, &by_name, f, f.intra);
    }
    return .{
        .by_id = by_id,
        .by_name = by_name,
        .by_name_multi = by_name_multi,
        .callers = callers,
        .callers_alloc = gpa,
    };
}

fn collectIntraCallers(
    gpa: std.mem.Allocator,
    callers: *std.AutoHashMap(FnId, std.ArrayList(CallerSite)),
    by_name: *const std.StringHashMap(*const Function),
    from: *const Function,
    atoms: []const Atom,
) !void {
    for (atoms) |atom| {
        switch (atom) {
            .call => |c| {
                var to_id: ?FnId = c.to;
                if (to_id == null) {
                    if (by_name.get(c.name)) |fp| to_id = fp.id;
                }
                const id = to_id orelse continue;
                const gop = try callers.getOrPut(id);
                if (!gop.found_existing) gop.value_ptr.* = .{};
                try gop.value_ptr.append(gpa, .{
                    .from = from,
                    .site = c.site,
                    .kind = c.kind,
                });
            },
            .branch => |b| for (b.arms) |arm| {
                try collectIntraCallers(gpa, callers, by_name, from, arm.seq);
            },
            .loop => |l| try collectIntraCallers(gpa, callers, by_name, from, l.body),
        }
    }
}

/// Render a call tree rooted at `root` to `out`, with branch/loop framing
/// and a fixed maximum depth. `arena` owns the recursion-guard set; allocate
/// from a short-lived arena per render call.
pub fn renderTrace(
    arena: std.mem.Allocator,
    out: *std.io.Writer,
    ctx: Ctx,
    root: *const Function,
    max_depth: u32,
) !void {
    var visited = std.AutoHashMap(FnId, void).init(arena);
    try renderFn(out, ctx, root, 0, max_depth, &visited);
}

/// Compact line-based renderer for the trace tree. Designed for LLM
/// consumers — strips file:line metadata (look up via callgraph_loc on
/// demand) so the trace is pure control-flow structure. Each line is
/// self-describing with the first two characters carrying all the type
/// information; no separator before the payload either.
///
///   `<depth><payload>`        → descended function call (the default)
///   `<depth><tag><payload>`   → tagged node (special case)
///
/// `<depth>` is a single base-36 char: `0`–`9` for 0–9, then `a`–`z`
/// for 10–35. `<tag>` is exactly one character drawn from the symbol
/// set below. Symbols never appear at the start of Zig identifiers, so
/// `line[1]` unambiguously distinguishes a tagged node from a descended
/// function-name payload.
///
/// Tags:
///   `^`  function at depth cap, body has callees (payload: name; trace
///        deeper to expand)
///   `@`  function with no callees in its body — typically AST-only
///        helpers the compiler inlined away. Never expands further;
///        deepening the trace will not help. (payload: name)
///   `~`  body shown elsewhere — followed by a single base-36 depth
///        char pointing at the line where the body was actually
///        rendered, then the function name. Either an ancestor on the
///        call path (recursion) or a fn already expanded earlier as a
///        sibling. Either way, scan upward for a line whose leading
///        char matches that depth and whose payload is this name.
///        Shape: `<this_depth>~<body_depth><name>`.
///   `&`  indirect call (payload: expression)
///   `!`  unresolved call (payload: name)
///   `%`  folded debug call (payload: name)
///   `=`  folded stdlib call (payload: name)
///   `?`  branch (payload: `if_else` or `switch`)
///   `*`  loop (no payload)
///   `>`  branch arm (payload: label, truncated at 80 chars)
///
/// Header line (always first):
///   `T fns=N cap=N d=N[ top=<name>/<count>][ cap_top=<n1>/<c1>,<n2>/<c2>,...]`
/// `cap_top` lists up to 3 fns reached at the depth cap, sorted by call-site
/// count desc. Tells the caller exactly which fn(s) to deepen next instead
/// of cranking depth blindly. Suppressed when every capped fn has only
/// one call site — in that case the `^` markers in the body already
/// locate them and `cap_top` adds no signal.
pub fn renderTraceCompact(
    arena: std.mem.Allocator,
    out: *std.io.Writer,
    ctx: Ctx,
    root: *const Function,
    max_depth: u32,
    stats: TraceStats,
) !void {
    try out.print("T fns={d} cap={d} d={d}", .{ stats.fns_visited, stats.at_cap, max_depth });
    if (stats.top_fanout > 0) {
        try out.print(" top={s}/{d}", .{ stats.top_name, stats.top_fanout });
    }
    // Suppress cap_top entirely when every entry has just one call site —
    // the `^` markers in the body already point at them and `/1` flags add
    // noise without distinguishing a hot spot. Emit it only when at least
    // one capped fn has 2+ call sites, which is the case where the field
    // tells the caller which subtree to deepen first.
    if (stats.cap_top.len > 0 and stats.cap_top[0].count > 1) {
        try out.writeAll(" cap_top=");
        for (stats.cap_top, 0..) |e, i| {
            if (i > 0) try out.writeByte(',');
            try out.print("{s}/{d}", .{ e.name, e.count });
        }
    }
    try out.writeAll("\n");

    // Two distinct fn-id maps. Values are the depth at which the fn's
    // body was rendered — emitted after `~` so a reader can scan to that
    // depth's earlier line instead of grepping the whole trace.
    //   `visited`  — ancestors on the current call path. Push on descend,
    //                pop on return. Catches recursion (same fn calling
    //                itself transitively) and emits `~<body_d>name`.
    //   `rendered` — every fn whose body we've already expanded ANYWHERE
    //                in this trace. Never pruned. Catches sibling repeats
    //                (e.g. SlabRef.unlock called 6× under the same parent)
    //                and collapses them to `~<body_d>name` instead of
    //                re-emitting the same subtree. Both sets share the
    //                `~` tag — the semantic ("look elsewhere for the
    //                body") is the same; the agent doesn't need to
    //                distinguish ancestor cycle from already-shown
    //                sibling.
    var visited = std.AutoHashMap(FnId, u32).init(arena);
    var rendered = std.AutoHashMap(FnId, u32).init(arena);
    try compactFn(out, ctx, root, 0, max_depth, &visited, &rendered);
}

fn compactDepth(out: *std.io.Writer, depth: u32) !void {
    // Base-36 single char (0-9, a-z). The renderTrace caller bounds depth
    // at max_depth (≤ 40 in practice; 36 logical levels here).
    const d = if (depth > 35) @as(u32, 35) else depth;
    const c: u8 = if (d < 10) '0' + @as(u8, @intCast(d)) else 'a' + @as(u8, @intCast(d - 10));
    try out.writeByte(c);
}

fn compactFn(
    out: *std.io.Writer,
    ctx: Ctx,
    f: *const Function,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
) RenderError!void {
    try compactDepth(out, depth);
    try out.writeAll(f.name);
    try out.writeAll("\n");
    // Mark this fn as rendered before walking its body so descendants that
    // call back into f collapse via the rendered-set check (in addition to
    // the visited-set ancestor check, which would also fire). Putting the
    // mark here — instead of in compactCall before the recursion — also
    // covers the root, which compactCall never sees. Storing `depth` lets
    // sibling-repeat `~` lines emit a forward reference back to the line
    // where this body lives.
    try rendered.put(f.id, depth);
    try compactSeq(out, ctx, f.intra, depth + 1, max_depth, visited, rendered);
}

/// Render a flat atom sequence (a fn body, branch arm, or loop body) with
/// adjacent-line dedup. When two or more consecutive call atoms collapse
/// to the same single-line tag (e.g. five `@arg` extractions in a row, or
/// three `^X.Y` capped leaves under a switch arm), emit one line with a
/// `×N` multiplier. Strict adjacency: any branch/loop/recursing call in
/// between breaks a run, so call-order semantics are preserved. Atoms
/// that produce no output (filtered assertions, hidden ref captures) are
/// transparent — they don't break adjacency, since the agent never sees
/// them in the rendered trace.
fn compactSeq(
    out: *std.io.Writer,
    ctx: Ctx,
    atoms: []const Atom,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
) RenderError!void {
    var i: usize = 0;
    while (i < atoms.len) {
        const atom = atoms[i];
        switch (atom) {
            .call => |c| {
                const shape = classifyCall(ctx, c, depth, max_depth, visited, rendered);
                switch (shape) {
                    .skip => {
                        i += 1;
                    },
                    .single => |line| {
                        var j = i + 1;
                        var count: u32 = 1;
                        while (j < atoms.len) : (j += 1) {
                            const next = atoms[j];
                            if (next != .call) break;
                            const next_shape = classifyCall(ctx, next.call, depth, max_depth, visited, rendered);
                            switch (next_shape) {
                                .skip => continue,
                                .single => |nl| {
                                    if (!callLineEql(line, nl)) break;
                                    count += 1;
                                },
                                .multi => break,
                            }
                        }
                        try emitCallLine(out, depth, line, count);
                        i = j;
                    },
                    .multi => {
                        try compactCall(out, ctx, c, depth, max_depth, visited, rendered);
                        i += 1;
                    },
                }
            },
            .branch, .loop => {
                try compactAtom(out, ctx, atom, depth, max_depth, visited, rendered);
                i += 1;
            },
        }
    }
}

const CallLine = struct {
    tag: u8,
    body_depth: u32,
    name: []const u8,
};

const CallShape = union(enum) {
    skip,
    single: CallLine,
    multi,
};

fn callLineEql(a: CallLine, b: CallLine) bool {
    if (a.tag != b.tag) return false;
    if (a.tag == '~' and a.body_depth != b.body_depth) return false;
    return std.mem.eql(u8, a.name, b.name);
}

/// Mirror of `compactCall`'s decision tree, returning what shape the
/// emission would take without actually writing. Must stay in lockstep
/// with `compactCall`; any new fold rule added there must be reflected
/// here or dedup will misclassify.
fn classifyCall(
    ctx: Ctx,
    c: Callee,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
) CallShape {
    if (ctx.hide_assertions and isAssertionName(c.name)) return .skip;
    if (ctx.hide_debug and isDebugName(c.name)) {
        return .{ .single = .{ .tag = '%', .body_depth = 0, .name = c.name } };
    }
    var fp: ?*const Function = null;
    if (c.to) |id| fp = ctx.by_id.get(id);
    if (fp == null) fp = ctx.by_name.get(c.name);
    if (fp == null) {
        if (c.kind == .indirect and ctx.hide_ref_captures and isTrivialRefCapture(c.name)) return .skip;
        const tag: u8 = if (c.kind == .indirect) '&' else '!';
        return .{ .single = .{ .tag = tag, .body_depth = 0, .name = c.name } };
    }
    const f = fp.?;
    if (ctx.excludes.len > 0 and matchExclude(f.name, ctx.excludes)) {
        return .{ .single = .{ .tag = '-', .body_depth = 0, .name = f.name } };
    }
    if (ctx.hide_library and isLibrary(f.name)) {
        return .{ .single = .{ .tag = '=', .body_depth = 0, .name = f.name } };
    }
    if (visited.get(f.id)) |body_depth| {
        return .{ .single = .{ .tag = '~', .body_depth = body_depth, .name = f.name } };
    }
    if (rendered.get(f.id)) |body_depth| {
        return .{ .single = .{ .tag = '~', .body_depth = body_depth, .name = f.name } };
    }
    if (f.intra.len == 0) {
        return .{ .single = .{ .tag = '@', .body_depth = 0, .name = f.name } };
    }
    if (depth + 1 >= max_depth) {
        return .{ .single = .{ .tag = '^', .body_depth = 0, .name = f.name } };
    }
    return .multi;
}

fn emitCallLine(out: *std.io.Writer, depth: u32, line: CallLine, count: u32) !void {
    try compactDepth(out, depth);
    try out.writeByte(line.tag);
    if (line.tag == '~') try compactDepth(out, line.body_depth);
    try out.writeAll(line.name);
    if (count > 1) try out.print(" ×{d}", .{count});
    try out.writeAll("\n");
}

fn compactAtom(
    out: *std.io.Writer,
    ctx: Ctx,
    atom: Atom,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
) RenderError!void {
    switch (atom) {
        .call => |c| try compactCall(out, ctx, c, depth, max_depth, visited, rendered),
        .branch => |b| try compactBranch(out, ctx, b, depth, max_depth, visited, rendered),
        .loop => |l| try compactLoop(out, ctx, l, depth, max_depth, visited, rendered),
    }
}

fn compactTagLine(out: *std.io.Writer, depth: u32, tag: u8, payload: []const u8) !void {
    try compactDepth(out, depth);
    try out.writeByte(tag);
    if (payload.len > 0) try out.writeAll(payload);
    try out.writeAll("\n");
}

/// `~` line with a forward reference to the depth where the body
/// actually rendered. Format: `<this_depth>~<body_depth><name>`.
fn compactBodyRef(out: *std.io.Writer, depth: u32, body_depth: u32, name: []const u8) !void {
    try compactDepth(out, depth);
    try out.writeByte('~');
    try compactDepth(out, body_depth);
    try out.writeAll(name);
    try out.writeAll("\n");
}

fn compactCall(
    out: *std.io.Writer,
    ctx: Ctx,
    c: Callee,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
) RenderError!void {
    if (ctx.hide_assertions and isAssertionName(c.name)) {
        return;
    }
    if (ctx.hide_debug and isDebugName(c.name)) {
        return compactTagLine(out, depth, '%', c.name);
    }
    var fp: ?*const Function = null;
    if (c.to) |id| fp = ctx.by_id.get(id);
    if (fp == null) fp = ctx.by_name.get(c.name);
    if (fp == null) {
        if (c.kind == .indirect and ctx.hide_ref_captures and isTrivialRefCapture(c.name)) {
            return;
        }
        const tag: u8 = if (c.kind == .indirect) '&' else '!';
        return compactTagLine(out, depth, tag, c.name);
    }
    const f = fp.?;
    if (ctx.excludes.len > 0 and matchExclude(f.name, ctx.excludes)) {
        return compactTagLine(out, depth, '-', f.name);
    }
    if (ctx.hide_library and isLibrary(f.name)) {
        return compactTagLine(out, depth, '=', f.name);
    }
    if (visited.get(f.id)) |body_depth| {
        return compactBodyRef(out, depth, body_depth, f.name);
    }
    // Sibling-repeat collapse: if we've already rendered this fn's body
    // somewhere earlier in the trace, emit `~<body_d>name` instead of
    // re-expanding the same subtree. Most kernel paths show this with
    // hot helpers like SlabRef.unlock or mintReply being called several
    // times under one parent; pre-dedup, the trace re-emitted the
    // identical 3–4 line subtree per occurrence. The body_depth points
    // at the line that holds the original expansion.
    if (rendered.get(f.id)) |body_depth| {
        return compactBodyRef(out, depth, body_depth, f.name);
    }
    if (f.intra.len == 0) {
        return compactTagLine(out, depth, '@', f.name);
    }
    if (depth + 1 >= max_depth) {
        return compactTagLine(out, depth, '^', f.name);
    }
    try visited.put(f.id, depth);
    defer _ = visited.remove(f.id);
    try compactFn(out, ctx, f, depth, max_depth, visited, rendered);
}

fn compactBranch(
    out: *std.io.Writer,
    ctx: Ctx,
    b: BranchAtom,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
) RenderError!void {
    const kind: []const u8 = switch (b.kind) {
        .if_else => "if_else",
        .switch_ => "switch",
    };
    try compactTagLine(out, depth, '?', kind);
    for (b.arms) |arm| {
        try compactTagLine(out, depth + 1, '>', shorten(arm.label, 80));
        try compactSeq(out, ctx, arm.seq, depth + 2, max_depth, visited, rendered);
    }
}

fn compactLoop(
    out: *std.io.Writer,
    ctx: Ctx,
    l: LoopAtom,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
) RenderError!void {
    try compactTagLine(out, depth, '*', "");
    try compactSeq(out, ctx, l.body, depth + 1, max_depth, visited, rendered);
}

/// Quick stats from a stats-only walk over the trace tree, mirroring the
/// pruning rules `renderTrace` would apply. Cheap to compute (no
/// formatting, no source reads). Returned counts let a caller emit a
/// one-line header before the tree so the consumer can decide whether
/// the depth cap was binding without scanning the rendered output.
pub const TraceStats = struct {
    /// Distinct kernel functions whose bodies were visited (after fold
    /// rules are applied — folded debug/stdlib leaves are not counted).
    fns_visited: u32 = 0,
    /// Calls that hit the depth cap and were emitted as `▸` leaves
    /// without descending. Non-zero here is the signal to crank depth.
    at_cap: u32 = 0,
    /// Function in the visited set with the most direct call atoms.
    /// Empty when the tree is trivial.
    top_name: []const u8 = "",
    top_loc: SourceLoc = .{ .file = "", .line = 0 },
    top_fanout: u32 = 0,
    /// Top capped fns ordered by how many call sites reach them at the
    /// depth cap. Lets the trace header tell the caller WHERE to deepen
    /// without scanning the body. Only populated when at_cap > 0.
    cap_top: []const CapEntry = &.{},

    pub const CapEntry = struct {
        name: []const u8,
        count: u32,
    };
};

/// Walk the trace tree rooted at `root` mirroring `renderTrace`'s pruning
/// rules, but skip all formatting. Used to produce the one-line summary
/// header that precedes a rendered trace.
pub fn statsTrace(
    arena: std.mem.Allocator,
    ctx: Ctx,
    root: *const Function,
    max_depth: u32,
) !TraceStats {
    // Mirror the rendering walk's two sets so the header summary matches
    // what the rendered tree actually contains. `rendered` persists across
    // siblings so a fn called many times under one parent counts once.
    var visited = std.AutoHashMap(FnId, u32).init(arena);
    var rendered = std.AutoHashMap(FnId, u32).init(arena);
    var stats: TraceStats = .{};
    var cap_counts = std.StringHashMap(u32).init(arena);
    try statsFn(ctx, root, 0, max_depth, &visited, &rendered, &stats, &cap_counts);
    stats.cap_top = try topCapNames(arena, &cap_counts, 3);
    return stats;
}

fn topCapNames(
    arena: std.mem.Allocator,
    counts: *const std.StringHashMap(u32),
    limit: usize,
) ![]TraceStats.CapEntry {
    if (counts.count() == 0) return &.{};
    var all = try arena.alloc(TraceStats.CapEntry, counts.count());
    var i: usize = 0;
    var it = counts.iterator();
    while (it.next()) |e| {
        all[i] = .{ .name = e.key_ptr.*, .count = e.value_ptr.* };
        i += 1;
    }
    const Sorter = struct {
        fn lt(_: void, a: TraceStats.CapEntry, b: TraceStats.CapEntry) bool {
            if (a.count != b.count) return a.count > b.count;
            return std.mem.lessThan(u8, a.name, b.name);
        }
    };
    std.mem.sort(TraceStats.CapEntry, all, {}, Sorter.lt);
    const n = @min(all.len, limit);
    return all[0..n];
}

fn statsFn(
    ctx: Ctx,
    f: *const Function,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
    stats: *TraceStats,
    cap_counts: *std.StringHashMap(u32),
) std.mem.Allocator.Error!void {
    stats.fns_visited += 1;
    try rendered.put(f.id, depth);
    // Fanout = number of *visible* call atoms in this function's body, after
    // pruning rules. Counts calls inside branches and loops too. This is the
    // metric that matches what the trace would actually render — IR
    // callees.len misses inlined-body calls and overcounts dead branches.
    const fanout = countVisibleCalls(ctx, f.intra);
    if (fanout > stats.top_fanout) {
        stats.top_fanout = fanout;
        stats.top_name = f.name;
        stats.top_loc = f.def_loc;
    }
    for (f.intra) |atom| try statsAtom(ctx, atom, depth + 1, max_depth, visited, rendered, stats, cap_counts);
}

fn countVisibleCalls(ctx: Ctx, atoms: []const Atom) u32 {
    var n: u32 = 0;
    for (atoms) |atom| {
        switch (atom) {
            .call => |c| {
                if (ctx.hide_assertions and isAssertionName(c.name)) continue;
                if (ctx.hide_debug and isDebugName(c.name)) continue;
                var fp: ?*const Function = null;
                if (c.to) |id| fp = ctx.by_id.get(id);
                if (fp == null) fp = ctx.by_name.get(c.name);
                if (fp) |f| {
                    if (ctx.excludes.len > 0 and matchExclude(f.name, ctx.excludes)) continue;
                    if (ctx.hide_library and isLibrary(f.name)) continue;
                }
                n += 1;
            },
            .branch => |b| for (b.arms) |arm| {
                n += countVisibleCalls(ctx, arm.seq);
            },
            .loop => |l| n += countVisibleCalls(ctx, l.body),
        }
    }
    return n;
}

fn statsAtom(
    ctx: Ctx,
    atom: Atom,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
    stats: *TraceStats,
    cap_counts: *std.StringHashMap(u32),
) std.mem.Allocator.Error!void {
    switch (atom) {
        .call => |c| try statsCall(ctx, c, depth, max_depth, visited, rendered, stats, cap_counts),
        .branch => |b| {
            for (b.arms) |arm| {
                for (arm.seq) |a| try statsAtom(ctx, a, depth, max_depth, visited, rendered, stats, cap_counts);
            }
        },
        .loop => |l| {
            for (l.body) |a| try statsAtom(ctx, a, depth, max_depth, visited, rendered, stats, cap_counts);
        },
    }
}

fn statsCall(
    ctx: Ctx,
    c: Callee,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, u32),
    rendered: *std.AutoHashMap(FnId, u32),
    stats: *TraceStats,
    cap_counts: *std.StringHashMap(u32),
) std.mem.Allocator.Error!void {
    if (ctx.hide_assertions and isAssertionName(c.name)) return;
    if (ctx.hide_debug and isDebugName(c.name)) return;
    var fp: ?*const Function = null;
    if (c.to) |id| fp = ctx.by_id.get(id);
    if (fp == null) fp = ctx.by_name.get(c.name);
    if (fp == null) return;
    const f = fp.?;
    if (ctx.excludes.len > 0 and matchExclude(f.name, ctx.excludes)) return;
    if (ctx.hide_library and isLibrary(f.name)) return;
    if (visited.contains(f.id)) return;
    // Sibling-repeat collapse: mirror compactCall's `rendered` check so
    // the header counts (fns/at_cap/cap_top) describe what's actually in
    // the body. A repeat sibling is rendered as `~name`, not as a fresh
    // descent or a `^` cap leaf, so it shouldn't bump fns_visited or at_cap.
    if (rendered.contains(f.id)) return;
    if (f.intra.len == 0) {
        // No-body leaf — counted as visited (it appears in the rendered
        // tree as `@name`) but never as `at_cap`, since deepening will
        // not expand it.
        stats.fns_visited += 1;
        try rendered.put(f.id, depth);
        return;
    }
    if (depth + 1 >= max_depth) {
        stats.at_cap += 1;
        const gop = try cap_counts.getOrPut(f.name);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
        return;
    }
    try visited.put(f.id, depth);
    defer _ = visited.remove(f.id);
    try statsFn(ctx, f, depth, max_depth, visited, rendered, stats, cap_counts);
}

fn renderFn(
    out: *std.io.Writer,
    ctx: Ctx,
    f: *const Function,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, void),
) RenderError!void {
    const indent = depth * 2;
    var name_buf: [256]u8 = undefined;
    var name_writer = std.io.Writer.fixed(&name_buf);
    if (f.is_ast_only) {
        try name_writer.print("{s} ↪ inlined", .{f.name});
    } else {
        try name_writer.writeAll(f.name);
    }
    try writePaddedName(out, prefixSpaces(indent), name_writer.buffered(), "");
    try writeLoc(out, f.def_loc, "");
    try out.writeAll("\n");

    if (f.intra.len == 0) {
        try writeIndent(out, indent + 2);
        try out.writeAll("(no calls)\n");
        return;
    }

    for (f.intra) |atom| {
        try renderAtom(out, ctx, atom, depth + 1, max_depth, visited);
    }
}

fn renderAtom(
    out: *std.io.Writer,
    ctx: Ctx,
    atom: Atom,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, void),
) RenderError!void {
    switch (atom) {
        .call => |c| try renderCall(out, ctx, c, depth, max_depth, visited),
        .branch => |b| try renderBranch(out, ctx, b, depth, max_depth, visited),
        .loop => |l| try renderLoop(out, ctx, l, depth, max_depth, visited),
    }
}

fn renderCall(
    out: *std.io.Writer,
    ctx: Ctx,
    c: Callee,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, void),
) RenderError!void {
    const indent = depth * 2;
    var fp: ?*const Function = null;
    if (c.to) |id| fp = ctx.by_id.get(id);
    if (fp == null) fp = ctx.by_name.get(c.name);

    if (ctx.hide_assertions and isAssertionName(c.name)) {
        return;
    }
    if (ctx.hide_debug and isDebugName(c.name)) {
        try writePaddedName(out, prefixSpaces(indent), "↓ debug", c.name);
        try writeLoc(out, c.site, "@ ");
        try out.writeAll("\n");
        return;
    }

    if (fp == null) {
        if (c.kind == .indirect and ctx.hide_ref_captures and isTrivialRefCapture(c.name)) {
            return;
        }
        if (c.kind == .indirect) {
            try writePaddedName(out, prefixSpaces(indent), "? indirect", c.name);
        } else {
            try writePaddedName(out, prefixSpaces(indent), c.name, "(no body)");
        }
        try writeLoc(out, c.site, "@ ");
        try out.writeAll("\n");
        return;
    }

    const f = fp.?;

    if (ctx.excludes.len > 0 and matchExclude(f.name, ctx.excludes)) {
        try writePaddedName(out, prefixSpaces(indent), "− excluded", f.name);
        try writeLoc(out, c.site, "@ ");
        try out.writeAll("\n");
        return;
    }

    if (ctx.hide_library and isLibrary(f.name)) {
        try writePaddedName(out, prefixSpaces(indent), "→ stdlib", f.name);
        try writeLoc(out, c.site, "@ ");
        try out.writeAll("\n");
        return;
    }

    if (visited.contains(f.id)) {
        try writePaddedName(out, prefixSpaces(indent), "↻ recursive", f.name);
        try writeLoc(out, c.site, "@ ");
        try out.writeAll("\n");
        return;
    }

    if (depth + 1 >= max_depth) {
        try writePaddedName(out, prefixSpaces(indent), "▸ ", f.name);
        try writeLoc(out, f.def_loc, "");
        try out.writeAll("\n");
        return;
    }

    try visited.put(f.id, {});
    defer _ = visited.remove(f.id);
    try renderFn(out, ctx, f, depth, max_depth, visited);
}

fn renderBranch(
    out: *std.io.Writer,
    ctx: Ctx,
    b: BranchAtom,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, void),
) RenderError!void {
    const indent = depth * 2;
    const tag: []const u8 = switch (b.kind) {
        .if_else => "if/else",
        .switch_ => "switch",
    };
    try writePaddedName(out, prefixSpaces(indent), tag, "");
    try writeLoc(out, b.loc, "");
    try out.writeAll("\n");

    for (b.arms) |arm| {
        try writeIndent(out, indent + 2);
        try out.print("[{s}]\n", .{shorten(arm.label, 64)});
        if (arm.seq.len == 0) {
            try writeIndent(out, indent + 4);
            try out.writeAll("(no calls)\n");
            continue;
        }
        for (arm.seq) |a| {
            try renderAtom(out, ctx, a, depth + 2, max_depth, visited);
        }
    }
}

fn renderLoop(
    out: *std.io.Writer,
    ctx: Ctx,
    l: LoopAtom,
    depth: u32,
    max_depth: u32,
    visited: *std.AutoHashMap(FnId, void),
) RenderError!void {
    const indent = depth * 2;
    try writePaddedName(out, prefixSpaces(indent), "↻ loop", "");
    try writeLoc(out, l.loc, "@ ");
    try out.writeAll("\n");
    if (l.body.len == 0) {
        try writeIndent(out, indent + 2);
        try out.writeAll("(no calls)\n");
        return;
    }
    for (l.body) |a| {
        try renderAtom(out, ctx, a, depth + 1, max_depth, visited);
    }
}

// ----------------------------------------------------------------- modules

/// Aggregate a graph's function-level call edges into module-level edges.
/// Module identity is derived from each function's `def_loc.file`: strip
/// the `kernel/` prefix and the `.zig` suffix, then truncate to the first
/// `level` path components. So `kernel/arch/x64/paging.zig` at level=1 is
/// `arch`, at level=2 is `arch.x64`, at level=0 is the full
/// `arch.x64.paging`. Intra-module edges (same source module → same target
/// module) are suppressed unless `include_intra` is set — at the layering
/// granularity people usually care about, the inter-module edges are the
/// signal.
pub const ModuleDirection = enum { out, in, both };

pub fn renderModuleGraph(
    allocator: std.mem.Allocator,
    out: *std.io.Writer,
    g: *const Graph,
    maps: Maps,
    level: u32,
    include_intra: bool,
    min_edges: u32,
    exclude_external: bool,
    direction: ModuleDirection,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Pre-compute each fn's module (interned strings owned by `arena`)
    // so we don't recompute or alias scratch buffers per edge.
    var fn_module = std.AutoHashMap(FnId, []const u8).init(arena);
    var module_pool = std.StringHashMap([]const u8).init(arena);
    for (g.functions) |*f| {
        const m = try internModule(arena, &module_pool, f.def_loc.file, level);
        if (m.len == 0) continue;
        try fn_module.put(f.id, m);
    }

    // (src_module, dst_module) -> count. Encoded as one string key with a
    // null byte separator so the StringHashMap key stays one slice.
    var edges = std.StringHashMap(u32).init(arena);

    for (g.functions) |*f| {
        const src_mod = fn_module.get(f.id) orelse continue;
        try collectModuleEdgesFromAtoms(arena, &edges, &fn_module, &module_pool, &maps, src_mod, f.intra, level);
    }

    var edge_list = std.ArrayList(Edge){};
    defer edge_list.deinit(arena);

    var hidden_edges: u32 = 0;
    var hidden_external: u32 = 0;
    var it = edges.iterator();
    while (it.next()) |e| {
        const sep = std.mem.indexOfScalar(u8, e.key_ptr.*, 0) orelse continue;
        const src = e.key_ptr.*[0..sep];
        const dst = e.key_ptr.*[sep + 1 ..];
        if (!include_intra and std.mem.eql(u8, src, dst)) continue;
        if (exclude_external and isExternalModule(src, dst)) {
            hidden_external += 1;
            continue;
        }
        if (e.value_ptr.* < min_edges) {
            hidden_edges += 1;
            continue;
        }
        try edge_list.append(arena, .{ .src = src, .dst = dst, .count = e.value_ptr.* });
    }

    var unique_modules = std.StringHashMap(void).init(arena);
    var fm_it = fn_module.valueIterator();
    while (fm_it.next()) |m| {
        if (exclude_external and isExternalModule(m.*, m.*)) continue;
        try unique_modules.put(m.*, {});
    }

    const total_edges = edge_list.items.len + hidden_edges + hidden_external;
    if (hidden_edges == 0 and hidden_external == 0) {
        try out.print(
            "module graph (level={d}{s}{s}{s}; direction={s}): {d} modules, {d} edges",
            .{
                level,
                if (include_intra) "" else "; intra suppressed",
                if (min_edges > 1) "; min_edges>1" else "",
                if (exclude_external) "; external excluded" else "",
                @tagName(direction),
                unique_modules.count(),
                edge_list.items.len,
            },
        );
    } else {
        try out.print(
            "module graph (level={d}{s}{s}{s}; direction={s}): {d} modules, {d} of {d} edges shown",
            .{
                level,
                if (include_intra) "" else "; intra suppressed",
                if (min_edges > 1) "; min_edges>1" else "",
                if (exclude_external) "; external excluded" else "",
                @tagName(direction),
                unique_modules.count(),
                edge_list.items.len,
                total_edges,
            },
        );
    }
    if (hidden_edges > 0 or hidden_external > 0) {
        try out.writeAll(" (");
        var wrote = false;
        if (hidden_external > 0) {
            try out.print("{d} to/from external", .{hidden_external});
            wrote = true;
        }
        if (hidden_edges > 0) {
            if (wrote) try out.writeAll(", ");
            try out.print("{d} below min_edges={d}", .{ hidden_edges, min_edges });
        }
        try out.writeAll(" hidden)");
    }
    try out.writeAll("\n\n");

    if (direction == .out or direction == .both) {
        if (direction == .both) try out.writeAll("# outbound (src -> dst)\n\n");
        try renderModuleEdgeList(out, edge_list.items, .out, arena);
    }
    if (direction == .both) try out.writeAll("\n");
    if (direction == .in or direction == .both) {
        if (direction == .both) try out.writeAll("# inbound (dst <- src)\n\n");
        try renderModuleEdgeList(out, edge_list.items, .in, arena);
    }
}

fn renderModuleEdgeList(
    out: *std.io.Writer,
    edges: []const Edge,
    direction: ModuleDirection,
    arena: std.mem.Allocator,
) !void {
    // Take a private mutable copy and sort it for the direction we're about
    // to render — `out` groups by src, `in` groups by dst.
    const sorted = try arena.dupe(Edge, edges);
    if (direction == .in) {
        std.mem.sort(Edge, sorted, {}, struct {
            fn lt(_: void, a: Edge, b: Edge) bool {
                const c = std.mem.order(u8, a.dst, b.dst);
                if (c != .eq) return c == .lt;
                if (a.count != b.count) return a.count > b.count;
                return std.mem.order(u8, a.src, b.src) == .lt;
            }
        }.lt);
        var prev_dst: []const u8 = "";
        for (sorted) |e| {
            if (!std.mem.eql(u8, e.dst, prev_dst)) {
                if (prev_dst.len > 0) try out.writeAll("\n");
                try out.print("{s}\n", .{e.dst});
                prev_dst = e.dst;
            }
            try out.print("  <- {s} ({d})\n", .{ e.src, e.count });
        }
    } else {
        std.mem.sort(Edge, sorted, {}, struct {
            fn lt(_: void, a: Edge, b: Edge) bool {
                const c = std.mem.order(u8, a.src, b.src);
                if (c != .eq) return c == .lt;
                if (a.count != b.count) return a.count > b.count;
                return std.mem.order(u8, a.dst, b.dst) == .lt;
            }
        }.lt);
        var prev_src: []const u8 = "";
        for (sorted) |e| {
            if (!std.mem.eql(u8, e.src, prev_src)) {
                if (prev_src.len > 0) try out.writeAll("\n");
                try out.print("{s}\n", .{e.src});
                prev_src = e.src;
            }
            try out.print("  -> {s} ({d})\n", .{ e.dst, e.count });
        }
    }
}

const Edge = struct { src: []const u8, dst: []const u8, count: u32 };

/// True when either endpoint is the synthetic `std` or `external` bucket
/// produced by `internModule` for non-kernel paths. Used to drop stdlib /
/// non-kernel noise from the module graph when the caller asks for kernel
/// layering only.
fn isExternalModule(src: []const u8, dst: []const u8) bool {
    return std.mem.eql(u8, src, "std") or std.mem.eql(u8, src, "external") or
        std.mem.eql(u8, dst, "std") or std.mem.eql(u8, dst, "external");
}

fn collectModuleEdgesFromAtoms(
    arena: std.mem.Allocator,
    edges: *std.StringHashMap(u32),
    fn_module: *std.AutoHashMap(FnId, []const u8),
    module_pool: *std.StringHashMap([]const u8),
    maps: *const Maps,
    src_mod: []const u8,
    atoms: []const Atom,
    level: u32,
) std.mem.Allocator.Error!void {
    for (atoms) |atom| {
        switch (atom) {
            .call => |c| {
                // Resolve the callee to find its def_loc.file (the source
                // of truth for the destination module). Fall back to the
                // call-site file only when the callee is unknown — that's
                // typically an indirect / unresolved edge anyway.
                var dst_mod: ?[]const u8 = null;
                var fp: ?*const Function = null;
                if (c.to) |id| fp = maps.by_id.get(id);
                if (fp == null) fp = maps.by_name.get(c.name);
                if (fp) |f| {
                    dst_mod = fn_module.get(f.id);
                }
                if (dst_mod == null) {
                    dst_mod = try internModule(arena, module_pool, c.site.file, level);
                }
                const dst = dst_mod.?;
                if (dst.len == 0) continue;

                const key = try arena.alloc(u8, src_mod.len + 1 + dst.len);
                @memcpy(key[0..src_mod.len], src_mod);
                key[src_mod.len] = 0;
                @memcpy(key[src_mod.len + 1 ..], dst);
                const gop = try edges.getOrPut(key);
                if (!gop.found_existing) {
                    gop.value_ptr.* = 0;
                } else {
                    // We had this key already; release the dup we just made.
                    arena.free(key);
                }
                gop.value_ptr.* += 1;
            },
            .branch => |b| for (b.arms) |arm| try collectModuleEdgesFromAtoms(arena, edges, fn_module, module_pool, maps, src_mod, arm.seq, level),
            .loop => |l| try collectModuleEdgesFromAtoms(arena, edges, fn_module, module_pool, maps, src_mod, l.body, level),
        }
    }
}

/// Derive a module identifier from a file path and intern it in `pool` so
/// repeated lookups return pointer-stable slices owned by `arena`.
fn internModule(
    arena: std.mem.Allocator,
    pool: *std.StringHashMap([]const u8),
    file_path: []const u8,
    level: u32,
) std.mem.Allocator.Error![]const u8 {
    if (pool.get(file_path)) |existing| return existing;

    var p = file_path;
    if (p.len == 0) return "";
    // Stdlib / non-kernel paths collapse to a single "std" bucket so the
    // module graph stays focused on kernel layering. Without this, paths
    // like `/usr/lib/zig/std/io.zig` render as `.usr` (after the `/` →
    // `.` substitution), which is useless noise.
    if (std.mem.indexOf(u8, p, "/std/") != null or
        std.mem.indexOf(u8, p, "/lib/zig/") != null or
        std.mem.startsWith(u8, p, "std/"))
    {
        const stdlib: []const u8 = "std";
        try pool.put(try arena.dupe(u8, file_path), stdlib);
        return stdlib;
    }
    if (std.mem.indexOf(u8, p, "/kernel/")) |i| p = p[i + 8 ..];
    if (std.mem.startsWith(u8, p, "kernel/")) p = p[7..];
    if (std.mem.endsWith(u8, p, ".zig")) p = p[0 .. p.len - 4];
    if (p.len == 0) return "";
    // Anything still starting with `/` is not under the kernel tree —
    // bucket it under "external" rather than letting `/foo/bar` become
    // `.foo.bar`.
    if (p[0] == '/') {
        const ext: []const u8 = "external";
        try pool.put(try arena.dupe(u8, file_path), ext);
        return ext;
    }

    if (level > 0) {
        var slashes: u32 = 0;
        for (p, 0..) |c, i| {
            if (c == '/') {
                slashes += 1;
                if (slashes == level) {
                    p = p[0..i];
                    break;
                }
            }
        }
    }

    const out = try arena.alloc(u8, p.len);
    for (p, 0..) |c, i| out[i] = if (c == '/') '.' else c;
    const interned: []const u8 = out;

    // Pool-key on the original file_path so repeat lookups are O(1); also
    // pool the derived module string so equality checks across fns can use
    // pointer comparison on identical modules.
    try pool.put(try arena.dupe(u8, file_path), interned);
    return interned;
}

// --------------------------------------------------------------------- source

/// Read the source body of `f` from disk and write it to `out` framed
/// with a header showing the path:line. Body extends from the def line
/// through the matching closing brace.
pub fn printFnSource(gpa: std.mem.Allocator, out: *std.io.Writer, f: *const Function) !void {
    // Compiler-synthesized symbols (`__zig_is_named_enum_value_*` etc.)
    // and IR-only fns the AST walk never matched have either an empty or
    // a non-absolute def_loc.file. openFileAbsolute *asserts* on
    // non-absolute paths and would crash the whole daemon — guard early.
    if (f.def_loc.file.len == 0) {
        try out.print("no source location for {s} (synthetic / IR-only fn)\n", .{f.name});
        return;
    }
    if (!std.fs.path.isAbsolute(f.def_loc.file)) {
        try out.print(
            "source path is not absolute for {s}: {s}\n",
            .{ f.name, f.def_loc.file },
        );
        return;
    }
    const file = std.fs.openFileAbsolute(f.def_loc.file, .{}) catch |err| {
        try out.print("open {s}: {s}\n", .{ f.def_loc.file, @errorName(err) });
        return;
    };
    defer file.close();
    const contents = try file.readToEndAlloc(gpa, 8 * 1024 * 1024);
    defer gpa.free(contents);

    const span = locateFnSpan(contents, f.def_loc.line);
    try out.print("--- {s}:{d}\n", .{ f.def_loc.file, f.def_loc.line });
    try out.writeAll(contents[span.start_off..span.end_off]);
    if (span.end_off == 0 or contents[span.end_off - 1] != '\n') try out.writeAll("\n");
    try out.writeAll("---\n");
}

const FnSpan = struct {
    start_off: usize,
    end_off: usize,
};

/// Walk forward from `start_line` until the first `{` opens and its match
/// closes. Strings and `//` line comments are skipped so braces inside
/// them don't throw off the depth counter.
pub fn locateFnSpan(contents: []const u8, start_line: u32) FnSpan {
    var line: u32 = 1;
    var off: usize = 0;
    while (off < contents.len and line < start_line) : (off += 1) {
        if (contents[off] == '\n') line += 1;
    }
    const start = off;

    var depth: i32 = 0;
    var seen_open = false;
    var i = off;
    const fallback_end: usize = @min(contents.len, off + 64 * 1024);
    while (i < contents.len) : (i += 1) {
        const c = contents[i];
        if (c == '/' and i + 1 < contents.len and contents[i + 1] == '/') {
            while (i < contents.len and contents[i] != '\n') : (i += 1) {}
            continue;
        }
        if (c == '"') {
            i += 1;
            while (i < contents.len) : (i += 1) {
                if (contents[i] == '\\' and i + 1 < contents.len) {
                    i += 1;
                    continue;
                }
                if (contents[i] == '"') break;
            }
            continue;
        }
        if (c == '\'') {
            i += 1;
            while (i < contents.len) : (i += 1) {
                if (contents[i] == '\\' and i + 1 < contents.len) {
                    i += 1;
                    continue;
                }
                if (contents[i] == '\'') break;
            }
            continue;
        }
        if (c == '{') {
            depth += 1;
            seen_open = true;
            continue;
        }
        if (c == '}') {
            depth -= 1;
            if (seen_open and depth == 0) {
                var end = i + 1;
                if (end < contents.len and contents[end] == '\n') end += 1;
                return .{ .start_off = start, .end_off = end };
            }
            continue;
        }
    }
    return .{ .start_off = start, .end_off = fallback_end };
}

// ------------------------------------------------------------------- helpers

pub fn writeIndent(out: *std.io.Writer, n: usize) !void {
    var i: usize = 0;
    while (i < n) : (i += 1) try out.writeAll(" ");
}

pub fn prefixSpaces(n: usize) []const u8 {
    const spaces = "                                                                "; // 64
    if (n > spaces.len) return spaces[0..spaces.len];
    return spaces[0..n];
}

pub fn writePaddedName(
    out: *std.io.Writer,
    prefix: []const u8,
    name: []const u8,
    aux: []const u8,
) !void {
    var written: usize = 0;
    try out.writeAll(prefix);
    written += prefix.len;
    try out.writeAll(name);
    written += name.len;
    if (aux.len > 0) {
        try out.writeAll("  ");
        try out.writeAll(aux);
        written += 2 + aux.len;
    }
    if (written < LOC_COLUMN) {
        const pad = LOC_COLUMN - written;
        var i: usize = 0;
        while (i < pad) : (i += 1) try out.writeAll(" ");
    } else {
        try out.writeAll("  ");
    }
}

pub fn writeLoc(out: *std.io.Writer, loc: SourceLoc, prefix: []const u8) !void {
    if (loc.file.len == 0) return;
    try out.writeAll(prefix);
    try out.print("{s}:{d}", .{ shortFile(loc.file), loc.line });
}

pub fn shortFile(p: []const u8) []const u8 {
    if (std.mem.indexOf(u8, p, "/kernel/")) |i| return p[i + 1 ..];
    return p;
}

pub fn shorten(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    return s[0..max];
}

pub fn isDebugName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "debug.") or
        std.mem.indexOf(u8, name, ".debug.") != null;
}

pub fn isLibrary(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "std.") or
        std.mem.startsWith(u8, name, "builtin.") or
        std.mem.startsWith(u8, name, "compiler_rt.");
}

/// True for assertion / unrecoverable-error calls that almost never carry
/// signal in a control-flow investigation: `debug.assert`, every
/// `debug.FullPanic.*` variant, and `builtin.returnError`. Used by the
/// `hide_assertions` filter to drop these calls entirely (no fold leaf
/// either) — they otherwise dominate ~10–25% of lines in syscall traces.
pub fn isAssertionName(name: []const u8) bool {
    if (std.mem.eql(u8, name, "debug.assert")) return true;
    if (std.mem.endsWith(u8, name, ".debug.assert")) return true;
    if (std.mem.startsWith(u8, name, "debug.FullPanic.")) return true;
    if (std.mem.indexOf(u8, name, ".debug.FullPanic.") != null) return true;
    if (std.mem.eql(u8, name, "builtin.returnError")) return true;
    return false;
}

pub fn kindLabel(k: EntryKind) []const u8 {
    return switch (k) {
        .syscall => "(syscall)",
        .trap => "(trap)",
        .irq => "(irq)",
        .boot => "(boot)",
        .manual => "(manual)",
    };
}

pub fn entryTag(f: Function) []const u8 {
    if (!f.is_entry) return "";
    if (f.entry_kind) |k| return kindLabel(k);
    return "(entry)";
}
