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
