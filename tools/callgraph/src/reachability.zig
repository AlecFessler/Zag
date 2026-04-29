// Forward reachability over IR call edges.
//
// Marks each `Function.reachable` based on whether the function can be
// reached from any discovered entry point by traversing direct call edges
// (and architecture-dispatch edges). Indirect / vtable edges have unknown
// targets post-monomorphization so we don't traverse them; `leaf_userspace`
// edges are synthetic terminators and are skipped too.
//
// The intent is to surface kernel functions the compiler kept in the IR but
// that nothing reachable from a syscall / trap / IRQ / boot entry actually
// calls — typically dead code, deprecated helpers, or routines only invoked
// indirectly through a function pointer the analysis can't follow.

const std = @import("std");

const types = @import("types.zig");

const FnId = types.FnId;
const Graph = types.Graph;

/// Stats from a reachability pass — handy for the startup log line.
pub const Stats = struct {
    total: usize,
    reachable: usize,
};

/// Walk forward from every entry point in `graph.entry_points`, marking each
/// reachable function's `reachable` field. Functions outside the visited set
/// are flipped to `reachable = false`. Allocator is used only for the
/// transient visited bitmap + worklist.
pub fn compute(allocator: std.mem.Allocator, graph: *Graph) !Stats {
    const fns = graph.functions;
    const visited = try allocator.alloc(bool, fns.len);
    defer allocator.free(visited);
    @memset(visited, false);

    var stack = std.ArrayList(FnId){};
    defer stack.deinit(allocator);

    for (graph.entry_points) |ep| {
        if (ep.fn_id >= fns.len) continue;
        if (visited[ep.fn_id]) continue;
        try stack.append(allocator, ep.fn_id);
        while (stack.pop()) |id| {
            if (id >= fns.len) continue;
            if (visited[id]) continue;
            visited[id] = true;
            const f = &fns[id];
            for (f.callees) |c| {
                if (!isTraversable(c.kind)) continue;
                const to = c.to orelse continue;
                if (to >= fns.len) continue;
                if (!visited[to]) try stack.append(allocator, to);
            }
        }
    }

    var reachable_count: usize = 0;
    for (fns, 0..) |*f, i| {
        f.reachable = visited[i];
        if (visited[i]) reachable_count += 1;
    }
    return .{ .total = fns.len, .reachable = reachable_count };
}

fn isTraversable(kind: types.EdgeKind) bool {
    return switch (kind) {
        .direct, .dispatch_x64, .dispatch_aarch64 => true,
        .vtable, .indirect, .leaf_userspace => false,
    };
}

/// For each function, count how many distinct entry points can transitively
/// reach it. Walks `Function.intra` atoms (the same source the trace uses)
/// rather than `f.callees` so inlined-body calls are followed — without
/// this, hub functions reached only through inlined wrappers (e.g.
/// `mintHandle`) would falsely report zero reach. Indirect call atoms are
/// still skipped (target unknown). Result is written to
/// `Function.entry_reach`. O(entries × visited_per_entry); fine at startup
/// for typical kernel sizes (~70 entries × ~1000 fns).
pub fn computeEntryReach(allocator: std.mem.Allocator, graph: *Graph) !void {
    const fns = graph.functions;
    const visited = try allocator.alloc(bool, fns.len);
    defer allocator.free(visited);

    // Pre-build a name → fn_id map so unresolved-by-id callees can still
    // be dereferenced (matches how the trace renderer falls back).
    var by_name = std.StringHashMap(FnId).init(allocator);
    defer by_name.deinit();
    for (fns) |*f| try by_name.put(f.name, f.id);

    var stack = std.ArrayList(FnId){};
    defer stack.deinit(allocator);

    for (fns) |*f| f.entry_reach = 0;

    for (graph.entry_points) |ep| {
        if (ep.fn_id >= fns.len) continue;
        @memset(visited, false);
        try stack.append(allocator, ep.fn_id);
        while (stack.pop()) |id| {
            if (id >= fns.len) continue;
            if (visited[id]) continue;
            visited[id] = true;
            try walkIntraTargets(allocator, fns, &by_name, fns[id].intra, visited, &stack);
        }
        for (fns, 0..) |*f, i| {
            if (visited[i]) f.entry_reach += 1;
        }
    }
}

fn walkIntraTargets(
    allocator: std.mem.Allocator,
    fns: []types.Function,
    by_name: *std.StringHashMap(FnId),
    atoms: []const types.Atom,
    visited: []bool,
    stack: *std.ArrayList(FnId),
) std.mem.Allocator.Error!void {
    for (atoms) |atom| {
        switch (atom) {
            .call => |c| {
                if (c.kind == .indirect or c.kind == .vtable or c.kind == .leaf_userspace) continue;
                var to: ?FnId = c.to;
                if (to == null) to = by_name.get(c.name);
                const id = to orelse continue;
                if (id >= fns.len) continue;
                if (!visited[id]) try stack.append(allocator, id);
            },
            .branch => |b| for (b.arms) |arm| try walkIntraTargets(allocator, fns, by_name, arm.seq, visited, stack),
            .loop => |l| try walkIntraTargets(allocator, fns, by_name, l.body, visited, stack),
        }
    }
}
