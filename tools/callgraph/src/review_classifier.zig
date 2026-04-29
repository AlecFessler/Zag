//! Classifies a commit's diff into reviewable Items.
//!
//! Pure function: takes parsed diff hunks + a graph, returns a list of
//! Items ready to be persisted via `review_store.save`. No I/O — the
//! caller fetches the diff (`git diff --unified=0`) and the per-commit
//! graph (via `commits.Registry`) and feeds them in.
//!
//! v1 simplifications (intentionally limited; see project plan):
//!   - Body changes are always non-trivial. We don't try to detect
//!     "just renamed a local var" — too easy to be wrong.
//!   - Orphan hunks default to `trivial = true` (no deps to view).
//!     Whitespace-/comment-only detection is a future tightening.
//!   - `symbol_added` / `symbol_removed` aren't distinguished from
//!     signature/body in v1 — the new graph is the only one we look
//!     at, so a removed symbol simply doesn't show up and a new symbol
//!     looks like a normal signature change.

const std = @import("std");

const review_store = @import("review_store.zig");
const types = @import("types.zig");

const Item = review_store.Item;
const ItemKind = review_store.ItemKind;
const DepsKind = review_store.DepsKind;

/// One hunk parsed from `git diff --unified=0`. Same shape as
/// `server.HunkRange`, redeclared here so the classifier doesn't pull
/// the http server into its dependency graph.
pub const Hunk = struct {
    old_start: u32,
    old_count: u32,
    new_start: u32,
    new_count: u32,
};

pub const FileHunks = struct {
    /// Repo-relative path (matches the `+++ b/<path>` line).
    path: []const u8,
    hunks: []const Hunk,
};

/// Classify diff hunks against a graph's known symbols.
///
/// Returned slice and all inner strings are allocated in `alloc`
/// (typically a request-scoped arena).
pub fn classify(
    alloc: std.mem.Allocator,
    files: []const FileHunks,
    graph: *const types.Graph,
) ![]Item {
    // Build per-file symbol tables. Functions get a derived line_end
    // from the next-fn boundary; definitions carry their own range.
    var fn_by_file = std.StringHashMap(std.ArrayList(FnRange)).init(alloc);
    var def_by_file = std.StringHashMap(std.ArrayList(DefRange)).init(alloc);

    for (graph.functions) |*fn_ptr| {
        if (fn_ptr.def_loc.file.len == 0) continue;
        // line == 0 means the IR/AST didn't pin a source location for
        // this function (synthesized helper, externally linked, etc.).
        // We can't reason about hunk overlap without a line, so skip.
        if (fn_ptr.def_loc.line == 0) continue;
        // Per-commit graphs carry absolute paths into the worktree
        // (`/var/tmp/cg-worktrees/<sha>/kernel/...`); diff hunks use
        // repo-relative paths (`kernel/...`). Normalize so the keys
        // align — same trick as the web view's `defLocToRepoRel`.
        const rel = repoRelativePath(fn_ptr.def_loc.file) orelse continue;
        const gop = try fn_by_file.getOrPut(rel);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.append(alloc, .{
            .qualified_name = fn_ptr.name,
            .line_start = fn_ptr.def_loc.line,
            // body_line_end is the closing brace line from the AST walker,
            // 0 when the join couldn't pin a matching AstFunction. The
            // post-sort fixup below substitutes the next-fn-boundary
            // heuristic for the 0 case.
            .line_end = fn_ptr.body_line_end,
        });
    }

    var fn_it = fn_by_file.iterator();
    while (fn_it.next()) |bucket| {
        const slice = bucket.value_ptr.items;
        std.mem.sort(FnRange, slice, {}, FnRange.lessThan);
        for (slice, 0..) |*rec, i| {
            // Prefer the AST-provided body_line_end. Fall back to the
            // next-fn-boundary heuristic only when AST didn't pin it.
            // Without this, hunks that fall in the doc-comment gap
            // between fn N and fn N+1 get misattributed to fn N.
            if (rec.line_end != 0 and rec.line_end >= rec.line_start) continue;
            if (i + 1 < slice.len) {
                const next_start = slice[i + 1].line_start;
                rec.line_end = @max(rec.line_start, next_start - 1);
            } else {
                rec.line_end = std.math.maxInt(u32);
            }
        }
    }

    for (graph.definitions) |*def_ptr| {
        if (def_ptr.file.len == 0) continue;
        if (def_ptr.line_start == 0) continue;
        // Skip plain `const X = ...` declarations (kind=constant). These
        // are usually import re-exports (`const x = zag.foo.x;`) or
        // simple value constants — neither has structural ripple via
        // def_deps, so flagging them as `type_changed` was misleading
        // noise. Hunks on these lines fall through to orphan_hunk
        // (trivial=true), which is the correct semantic.
        if (def_ptr.kind == .constant) continue;
        const rel = repoRelativePath(def_ptr.file) orelse continue;
        const gop = try def_by_file.getOrPut(rel);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.append(alloc, .{
            .qualified_name = def_ptr.qualified_name,
            .line_start = def_ptr.line_start,
            .line_end = if (def_ptr.line_end == 0) def_ptr.line_start else def_ptr.line_end,
            .kind = def_ptr.kind,
        });
    }

    // Group hunks by claimed symbol; track unclaimed for orphan emission.
    // Use the qualified_name as map key so a single Item is produced
    // per symbol even when multiple hunks touch it.
    var per_symbol_fn = std.StringArrayHashMap(SymbolAccum(FnRange)).init(alloc);
    var per_symbol_def = std.StringArrayHashMap(SymbolAccum(DefRange)).init(alloc);
    var orphans = std.ArrayList(OrphanHunk){};

    for (files) |fh| {
        const fns_slice: []const FnRange = if (fn_by_file.get(fh.path)) |list|
            list.items
        else
            &.{};
        const defs_slice: []const DefRange = if (def_by_file.get(fh.path)) |list|
            list.items
        else
            &.{};

        for (fh.hunks) |h| {
            // For pure-deletion hunks (count=0) the new_start points to
            // the line *before* which the deletion lived — treat as a
            // single boundary line, matching the frontend overlap test.
            const span = if (h.new_count == 0) 1 else h.new_count;
            const hstart = h.new_start;
            const hend = hstart + span - 1;

            // Prefer functions over definitions when both overlap — a
            // function is the more specific unit.
            var claimed = false;
            for (fns_slice) |fn_rec| {
                if (hend < fn_rec.line_start) continue;
                if (hstart > fn_rec.line_end) continue;
                const gop = try per_symbol_fn.getOrPut(fn_rec.qualified_name);
                if (!gop.found_existing) gop.value_ptr.* = .{
                    .symbol = fn_rec,
                    .file = fh.path,
                    .hunks = .{},
                    .signature_touched = false,
                };
                try gop.value_ptr.hunks.append(alloc, h);
                if (hstart <= fn_rec.line_start and fn_rec.line_start <= hend) {
                    gop.value_ptr.signature_touched = true;
                }
                claimed = true;
                break;
            }
            if (claimed) continue;

            for (defs_slice) |def_rec| {
                if (hend < def_rec.line_start) continue;
                if (hstart > def_rec.line_end) continue;
                const gop = try per_symbol_def.getOrPut(def_rec.qualified_name);
                if (!gop.found_existing) gop.value_ptr.* = .{
                    .symbol = def_rec,
                    .file = fh.path,
                    .hunks = .{},
                    .signature_touched = false,
                };
                try gop.value_ptr.hunks.append(alloc, h);
                claimed = true;
                break;
            }
            if (claimed) continue;

            try orphans.append(alloc, .{
                .file = fh.path,
                .hunk = h,
            });
        }
    }

    // Materialize Items. Order: function symbols (by file/line) →
    // definition symbols (by file/line) → orphans (by file/line). The
    // ordering doesn't affect correctness but it makes the items list
    // pleasant for an agent reading top-to-bottom.
    var out = std.ArrayList(Item){};

    {
        const FnEntry = struct {
            file: []const u8,
            qname: []const u8,
            line_start: u32,
            line_end: u32,
            sig: bool,
            hunks: []const Hunk,
        };
        var entries = std.ArrayList(FnEntry){};
        var it = per_symbol_fn.iterator();
        while (it.next()) |e| {
            try entries.append(alloc, .{
                .file = e.value_ptr.file,
                .qname = e.key_ptr.*,
                .line_start = e.value_ptr.symbol.line_start,
                .line_end = e.value_ptr.symbol.line_end,
                .sig = e.value_ptr.signature_touched,
                .hunks = e.value_ptr.hunks.items,
            });
        }
        std.mem.sort(FnEntry, entries.items, {}, struct {
            fn lt(_: void, a: FnEntry, b: FnEntry) bool {
                const c = std.mem.order(u8, a.file, b.file);
                if (c != .eq) return c == .lt;
                return a.line_start < b.line_start;
            }
        }.lt);
        for (entries.items) |e| {
            const kind: ItemKind = if (e.sig) .symbol_signature else .symbol_body;
            const deps_kind: DepsKind = if (e.sig) .callers_callees else .callers;
            const span_end = lastTouchedLine(e.hunks);
            try out.append(alloc, .{
                .id = try std.fmt.allocPrint(alloc, "sym:{s}", .{e.qname}),
                .kind = kind,
                .deps_kind = deps_kind,
                .file = try alloc.dupe(u8, e.file),
                .loc = try std.fmt.allocPrint(alloc, "L{d}-L{d}", .{ e.line_start, span_end }),
                .qualified_name = try alloc.dupe(u8, e.qname),
                .deps_required = null,
                .deps_viewed = &.{},
                .checked_off = false,
                .trivial = false,
                .notes = null,
            });
        }
    }

    {
        const DefEntry = struct {
            file: []const u8,
            qname: []const u8,
            line_start: u32,
            line_end: u32,
            hunks: []const Hunk,
        };
        var entries = std.ArrayList(DefEntry){};
        var it = per_symbol_def.iterator();
        while (it.next()) |e| {
            try entries.append(alloc, .{
                .file = e.value_ptr.file,
                .qname = e.key_ptr.*,
                .line_start = e.value_ptr.symbol.line_start,
                .line_end = e.value_ptr.symbol.line_end,
                .hunks = e.value_ptr.hunks.items,
            });
        }
        std.mem.sort(DefEntry, entries.items, {}, struct {
            fn lt(_: void, a: DefEntry, b: DefEntry) bool {
                const c = std.mem.order(u8, a.file, b.file);
                if (c != .eq) return c == .lt;
                return a.line_start < b.line_start;
            }
        }.lt);
        for (entries.items) |e| {
            try out.append(alloc, .{
                .id = try std.fmt.allocPrint(alloc, "sym:{s}", .{e.qname}),
                .kind = .type_changed,
                .deps_kind = .readers_writers,
                .file = try alloc.dupe(u8, e.file),
                .loc = try std.fmt.allocPrint(alloc, "L{d}-L{d}", .{ e.line_start, e.line_end }),
                .qualified_name = try alloc.dupe(u8, e.qname),
                .deps_required = null,
                .deps_viewed = &.{},
                .checked_off = false,
                .trivial = false,
                .notes = null,
            });
        }
    }

    {
        std.mem.sort(OrphanHunk, orphans.items, {}, struct {
            fn lt(_: void, a: OrphanHunk, b: OrphanHunk) bool {
                const c = std.mem.order(u8, a.file, b.file);
                if (c != .eq) return c == .lt;
                return a.hunk.new_start < b.hunk.new_start;
            }
        }.lt);
        for (orphans.items) |o| {
            const span = if (o.hunk.new_count == 0) 1 else o.hunk.new_count;
            const hend = o.hunk.new_start + span - 1;
            try out.append(alloc, .{
                .id = try std.fmt.allocPrint(alloc, "hunk:{s}:{d}-{d}", .{ o.file, o.hunk.new_start, hend }),
                .kind = .orphan_hunk,
                .deps_kind = .none,
                .file = try alloc.dupe(u8, o.file),
                .loc = try std.fmt.allocPrint(alloc, "L{d}-L{d}", .{ o.hunk.new_start, hend }),
                .qualified_name = null,
                .deps_required = null,
                .deps_viewed = &.{},
                .checked_off = false,
                .trivial = true,
                .notes = null,
            });
        }
    }

    return try out.toOwnedSlice(alloc);
}

// ---- Internal helpers ----------------------------------------------------

const FnRange = struct {
    qualified_name: []const u8,
    line_start: u32,
    line_end: u32,

    fn lessThan(_: void, a: FnRange, b: FnRange) bool {
        return a.line_start < b.line_start;
    }
};

const DefRange = struct {
    qualified_name: []const u8,
    line_start: u32,
    line_end: u32,
    kind: types.DefKind,
};

fn SymbolAccum(comptime SymT: type) type {
    return struct {
        symbol: SymT,
        file: []const u8,
        hunks: std.ArrayList(Hunk),
        signature_touched: bool,
    };
}

const OrphanHunk = struct {
    file: []const u8,
    hunk: Hunk,
};

/// Map a graph's def_loc.file (which may be absolute, e.g.
/// `/var/tmp/cg-worktrees/<sha>/kernel/...`) to a repo-relative path
/// matching the diff hunks' `kernel/...` form. Mirrors the web view's
/// `defLocToRepoRel`. Returns null when the path doesn't match either
/// shape — the caller drops the symbol from per-file overlap entirely.
///
/// Note: this is hardcoded for the `kernel/` top-level dir. Same
/// limitation the frontend lives with. If the callgraph tool grows
/// support for non-kernel projects this will need to take a configured
/// prefix.
pub fn repoRelativePath(file: []const u8) ?[]const u8 {
    if (file.len == 0) return null;
    const marker = "/kernel/";
    if (std.mem.lastIndexOf(u8, file, marker)) |idx| {
        return file[idx + 1 ..];
    }
    if (std.mem.startsWith(u8, file, "kernel/")) return file;
    return null;
}

fn lastTouchedLine(hunks: []const Hunk) u32 {
    var max_end: u32 = 0;
    for (hunks) |h| {
        const span = if (h.new_count == 0) 1 else h.new_count;
        const end = h.new_start + span - 1;
        if (end > max_end) max_end = end;
    }
    return max_end;
}

// ---- Tests ---------------------------------------------------------------

const testing = std.testing;

fn makeFn(id: types.FnId, name: []const u8, file: []const u8, line: u32) types.Function {
    return .{
        .id = id,
        .name = name,
        .mangled = name,
        .def_loc = .{ .file = file, .line = line, .col = 0 },
        .callees = &.{},
    };
}

fn makeDef(id: types.DefId, qname: []const u8, file: []const u8, ls: u32, le: u32, kind: types.DefKind) types.Definition {
    return .{
        .id = id,
        .name = qname,
        .qualified_name = qname,
        .file = file,
        .line_start = ls,
        .line_end = le,
        .kind = kind,
    };
}

test "classify: hunk inside fn body emits symbol_body with deps_kind=callers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{
        makeFn(0, "foo.bar", "kernel/foo.zig", 10),
        makeFn(1, "foo.next", "kernel/foo.zig", 100),
    };
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &.{},
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/foo.zig",
            .hunks = &.{
                .{ .old_start = 20, .old_count = 1, .new_start = 20, .new_count = 1 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 1), items.len);
    try testing.expect(items[0].kind == .symbol_body);
    try testing.expect(items[0].deps_kind == .callers);
    try testing.expectEqualStrings("sym:foo.bar", items[0].id);
    try testing.expectEqualStrings("foo.bar", items[0].qualified_name.?);
    try testing.expect(items[0].deps_required == null);
    try testing.expect(!items[0].trivial);
}

test "classify: hunk that includes def_loc line emits symbol_signature with deps_kind=callers_callees" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{makeFn(0, "foo.bar", "kernel/foo.zig", 10)};
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &.{},
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/foo.zig",
            .hunks = &.{
                .{ .old_start = 10, .old_count = 1, .new_start = 10, .new_count = 1 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 1), items.len);
    try testing.expect(items[0].kind == .symbol_signature);
    try testing.expect(items[0].deps_kind == .callers_callees);
}

test "classify: definition hunk emits type_changed with deps_kind=readers_writers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var defs = [_]types.Definition{
        makeDef(0, "foo.Config", "kernel/foo.zig", 5, 15, .struct_),
    };
    const graph = types.Graph{
        .functions = &.{},
        .entry_points = &.{},
        .definitions = &defs,
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/foo.zig",
            .hunks = &.{
                .{ .old_start = 8, .old_count = 2, .new_start = 8, .new_count = 2 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 1), items.len);
    try testing.expect(items[0].kind == .type_changed);
    try testing.expect(items[0].deps_kind == .readers_writers);
    try testing.expectEqualStrings("sym:foo.Config", items[0].id);
}

test "classify: orphan hunk (no overlap) is trivial with deps_kind=none" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{makeFn(0, "foo.bar", "kernel/foo.zig", 100)};
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &.{},
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/foo.zig",
            .hunks = &.{
                .{ .old_start = 1, .old_count = 1, .new_start = 1, .new_count = 1 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 1), items.len);
    try testing.expect(items[0].kind == .orphan_hunk);
    try testing.expect(items[0].deps_kind == .none);
    try testing.expect(items[0].trivial);
    try testing.expect(items[0].qualified_name == null);
    try testing.expectEqualStrings("hunk:kernel/foo.zig:1-1", items[0].id);
}

test "classify: multiple hunks in one fn collapse into a single Item" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{
        makeFn(0, "foo.bar", "kernel/foo.zig", 10),
        makeFn(1, "foo.next", "kernel/foo.zig", 200),
    };
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &.{},
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/foo.zig",
            .hunks = &.{
                .{ .old_start = 20, .old_count = 1, .new_start = 20, .new_count = 1 },
                .{ .old_start = 50, .old_count = 1, .new_start = 50, .new_count = 1 },
                .{ .old_start = 80, .old_count = 2, .new_start = 80, .new_count = 2 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 1), items.len);
    try testing.expect(items[0].kind == .symbol_body);
    // Loc should span from fn start to last touched line.
    try testing.expectEqualStrings("L10-L81", items[0].loc);
}

test "classify: function preferred over definition when both overlap a hunk" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{makeFn(0, "foo.bar", "kernel/foo.zig", 10)};
    var defs = [_]types.Definition{makeDef(0, "foo.Bag", "kernel/foo.zig", 5, 50, .struct_)};
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &defs,
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/foo.zig",
            .hunks = &.{
                .{ .old_start = 20, .old_count = 1, .new_start = 20, .new_count = 1 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 1), items.len);
    // Function wins over definition.
    try testing.expectEqualStrings("foo.bar", items[0].qualified_name.?);
    try testing.expect(items[0].kind == .symbol_body);
}

test "classify: pure-deletion hunk (new_count=0) still maps to enclosing fn" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{
        makeFn(0, "foo.bar", "kernel/foo.zig", 10),
        makeFn(1, "foo.next", "kernel/foo.zig", 100),
    };
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &.{},
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/foo.zig",
            .hunks = &.{
                .{ .old_start = 30, .old_count = 5, .new_start = 30, .new_count = 0 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 1), items.len);
    try testing.expect(items[0].kind == .symbol_body);
    try testing.expectEqualStrings("foo.bar", items[0].qualified_name.?);
}

test "classify: items are emitted in stable file/line order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{
        makeFn(0, "z.first", "kernel/z.zig", 10),
        makeFn(1, "z.second", "kernel/z.zig", 100),
        makeFn(2, "a.solo", "kernel/a.zig", 5),
    };
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &.{},
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/z.zig",
            .hunks = &.{
                .{ .old_start = 110, .old_count = 1, .new_start = 110, .new_count = 1 },
                .{ .old_start = 20, .old_count = 1, .new_start = 20, .new_count = 1 },
            },
        },
        .{
            .path = "kernel/a.zig",
            .hunks = &.{
                .{ .old_start = 10, .old_count = 1, .new_start = 10, .new_count = 1 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 3), items.len);
    try testing.expectEqualStrings("a.solo", items[0].qualified_name.?);
    try testing.expectEqualStrings("z.first", items[1].qualified_name.?);
    try testing.expectEqualStrings("z.second", items[2].qualified_name.?);
}

test "classify: orphan hunks come after symbol items" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{makeFn(0, "foo.bar", "kernel/foo.zig", 50)};
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &.{},
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/foo.zig",
            .hunks = &.{
                .{ .old_start = 1, .old_count = 1, .new_start = 1, .new_count = 1 },
                .{ .old_start = 60, .old_count = 1, .new_start = 60, .new_count = 1 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expect(items[0].kind == .symbol_body);
    try testing.expect(items[1].kind == .orphan_hunk);
}

test "classify: file with no hunks emits no items even if it has symbols" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{makeFn(0, "foo.bar", "kernel/foo.zig", 10)};
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &.{},
    };
    const items = try classify(a, &([_]FileHunks{}), &graph);
    try testing.expectEqual(@as(usize, 0), items.len);
}

test "classify: empty graph + non-empty hunks → all orphans" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const graph = types.Graph{
        .functions = &.{},
        .entry_points = &.{},
        .definitions = &.{},
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/x.zig",
            .hunks = &.{
                .{ .old_start = 1, .old_count = 1, .new_start = 1, .new_count = 1 },
                .{ .old_start = 5, .old_count = 1, .new_start = 5, .new_count = 1 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 2), items.len);
    for (items) |it| try testing.expect(it.kind == .orphan_hunk);
}

test "classify: hunk in file not in any symbol's file → orphan" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fns = [_]types.Function{makeFn(0, "foo.bar", "kernel/foo.zig", 10)};
    const graph = types.Graph{
        .functions = &fns,
        .entry_points = &.{},
        .definitions = &.{},
    };
    const files = [_]FileHunks{
        .{
            .path = "kernel/other.zig",
            .hunks = &.{
                .{ .old_start = 10, .old_count = 1, .new_start = 10, .new_count = 1 },
            },
        },
    };

    const items = try classify(a, &files, &graph);
    try testing.expectEqual(@as(usize, 1), items.len);
    try testing.expect(items[0].kind == .orphan_hunk);
    try testing.expectEqualStrings("kernel/other.zig", items[0].file);
}
